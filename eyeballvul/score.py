import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, cast

from litellm import completion, supports_function_calling
from pydantic import BaseModel, model_validator
from sqlmodel import Session, create_engine, select
from typeguard import typechecked

from eyeballvul.config.config_loader import Config
from eyeballvul.models.eyeballvul import EyeballvulItem
from eyeballvul.util import get_str_weak_hash

instructions_template = """
An AI vulnerability detection tool has analyzed a project and come up with the following lead:

<vulnerability_submission>
{vuln_submission}
</vulnerability_submission>

Your task is to score this lead based uniquely on whether it corresponds to one of the actual vulnerabilities displayed below.

The score should be 1 if the lead corresponds to one of the vulnerabilities below, and 0 if it doesn't correspond to any of them, or if it kind of corresponds to one, but is significantly off or imprecise (for instance if it's overly broad, or doesn't mention a realistic attack vector).

If and only if the score is 1, the corresponding real vulnerability ID must be returned. It is extracted from the "id" field of the vulnerability.

The real vulnerabilities are as follows:
<vulnerabilities>
{real_vulns}
</vulnerabilities>

Use the tool "return_score" to return your response.
"""
instruction_template_hash = get_str_weak_hash(instructions_template)[:20]


@dataclass
class Stats(BaseModel):
    """
    False negatives, true positives, and false positives.

    False positives may be None if this object is part of a larger StatsWithCutoff object, as the
    false positives apply to the whole set of vulnerabilities, not just the ones before or after a
    certain date.
    """

    fn: int
    tp: int
    fp: int | None = None


@dataclass
@typechecked
class StatsWithCutoff(BaseModel):
    """Similar to `Stats`, but with separate false negative and true positive counts before and
    after a cutoff."""

    fp: int
    before: Stats
    after: Stats


class EyeballvulScore(BaseModel):
    """
    Representation of the result of scoring a model's attempt at finding vulnerabilities.

    The `stats` attribute contains the false negatives, true positives, and false positives. The `mapping` attribute is a dictionary mapping the index of each vulnerability submission to the ID of the real vulnerability it corresponds to (if any). The `vuln_dates` attribute is a dictionary mapping vulnerability IDs to their publication date. The `scoring_model` attribute is the name of the scoring model used.
    """

    stats: Stats
    mapping: dict[int, str]
    vuln_dates: dict[str, datetime]
    scoring_model: str
    type: Literal["llm"]
    instruction_template_hash: str = instruction_template_hash

    @model_validator(mode="after")
    def check_stats(self) -> "EyeballvulScore":
        if self.stats.fp is None:
            raise ValueError(
                "fp can't be None in the EyeballvulStats object given to EyeballvulScore."
            )
        return self

    def stats_with_cutoff(
        self,
        cutoff_date: datetime,
    ) -> Stats | StatsWithCutoff:
        vulns_before = {vuln_id for vuln_id, date in self.vuln_dates.items() if date < cutoff_date}
        vulns_after = {vuln_id for vuln_id, date in self.vuln_dates.items() if date >= cutoff_date}
        vulns_hit = set(self.mapping.values())
        tp_before = len(vulns_before & vulns_hit)
        fn_before = len(vulns_before - vulns_hit)
        tp_after = len(vulns_after & vulns_hit)
        fn_after = len(vulns_after - vulns_hit)
        return StatsWithCutoff(
            fp=cast(int, self.stats.fp),
            before=Stats(fn=fn_before, tp=tp_before),
            after=Stats(fn=fn_after, tp=tp_after),
        )


@typechecked
def score_one(
    vuln_submission: str, real_vulns: list[EyeballvulItem], scoring_model: str
) -> tuple[int, str | None]:
    real_vulns_formats: list[str] = []
    for vuln in real_vulns:
        real_vulns_formats.append(json.dumps({"id": vuln.id, "details": vuln.details}, indent=2))
    real_vulns_str = "- " + "\n- ".join(real_vulns_formats)
    prompt = instructions_template.format(
        vuln_submission=vuln_submission, real_vulns=real_vulns_str
    )
    response = completion(
        model=scoring_model,
        messages=[{"content": prompt, "role": "user"}],
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "return_score",
                    "description": "return the score for the vulnerability submission",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "score": {
                                "type": "number",
                                "description": "the score for the vulnerability submission. Must be 0 or 1",
                            },
                            "corresponds_to": {
                                "type": "string",
                                "description": "the ID of the vulnerability that the submission corresponds to, if and only if the score is 1",
                            },
                        },
                        "required": ["score"],
                    },
                },
            }
        ],
        tool_choice={"type": "function", "function": {"name": "return_score"}},
    )
    content = response.choices[0].message
    arguments_str = content.tool_calls[0].function.arguments
    arguments_dict = json.loads(arguments_str)
    if "score" not in arguments_dict:
        raise ValueError(f"Invalid tool use: '{arguments_str}'. `score` parameter is missing.")
    score = int(arguments_dict["score"])
    if score not in (0, 1):
        raise ValueError(f"Invalid score: {score}. Must be 0 or 1.")
    if score == 1 and "corresponds_to" not in arguments_dict:
        raise ValueError("Score of 1 given but the `corresponds_to` parameter is not set.")
    real_vuln_ids = [vuln.id for vuln in real_vulns]
    if score == 1 and arguments_dict["corresponds_to"] not in real_vuln_ids:
        raise ValueError(
            f"Score of 1 given but the `corresponds_to` parameter ('{arguments_dict['corresponds_to']}') is not a valid vulnerability ID. Valid IDs: {real_vuln_ids}."
        )
    return (score, arguments_dict.get("corresponds_to"))


@typechecked
def compute_score(
    commit_hash: str,
    vulns_submission: list[str],
    scoring_model: str = Config.scoring_model,
    score_one_fn: Callable = score_one,
) -> EyeballvulScore:
    """
    Score a model's response (`vulns_submission`) against the real list of vulnerabilities at
    `commit_hash`.

    Returns an `EyeballvulScore` object. See its documentation for further information.

    The value in `Config.scoring_model` is used by default for the scoring model, but this can be changed with the `scoring_model` argument. The model name should be a valid LiteLLM model name, and support function calling / tool use.

    It's possible to supply a custom `score_one_fn` function, which must have the same signature as `score_one` (the one used by default).
    """
    if not supports_function_calling(scoring_model):
        raise ValueError(f"The model {scoring_model} doesn't support function calling.")
    engine = create_engine(f"sqlite:///{Config.paths.db}/eyeballvul.db")
    with Session(engine) as session:
        real_vulns = list(
            session.exec(
                select(EyeballvulItem).where(EyeballvulItem.commits.contains(commit_hash))  # type: ignore[attr-defined]
            ).all()
        )
    real_vulns_hit = set()
    total_score = 0
    real_vuln_mapping = {}
    for i, vuln_submission in enumerate(vulns_submission):
        score, corresponds_to = score_one_fn(vuln_submission, real_vulns, scoring_model)
        if corresponds_to:
            real_vulns_hit.add(corresponds_to)
            real_vuln_mapping[i] = corresponds_to
            total_score += score
    tp = len(real_vulns_hit)
    fp = len(vulns_submission) - total_score
    fn = len(real_vulns) - tp
    return EyeballvulScore(
        stats=Stats(fp=fp, fn=fn, tp=tp),
        mapping=real_vuln_mapping,
        vuln_dates={vuln.id: vuln.published for vuln in real_vulns},
        type="llm",
        scoring_model=scoring_model,
    )
