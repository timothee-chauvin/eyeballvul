# eyeballvul

eyeballvul is an open-source benchmark designed to enable the evaluation of [SAST](https://en.wikipedia.org/wiki/Static_application_security_testing) vulnerability detection tools, especially ones based on language models, designed to be future-proof.

While most benchmarks eventually make it into the training data of language models, eyeballvul is designed to be continuously updated from the data source of CVEs in open-source repositories. This means that it will remain relevant as long as models have a reasonably delayed training data cutoff, by evaluating on the subset of the vulnerabilities that were published after the training data cutoff of the considered model. The current goal is to update it weekly.

At a high level, eyeballvul converts the data stream of CVEs in open-source repositories into a small set of commits for each repository, and a set of vulnerabilities present at each of these commits.

The typical use case that this benchmark enables is the following:
1. select a list of repositories and commits for which there is at least one vulnerability published after some date;
1. run a SAST tool (typically LLM-based) on the source code at each of these commits;
1. compare the results of the SAST tool with the list of known vulnerabilities for each commit, especially the ones that were published after the training data cutoff.

eyeballvul currently contains 28,158 vulnerabilities, in 7,450 commits and 6,441 repositories.

## How to use
If you simply want to use eyeballvul (not build it), all you need is [poetry](https://python-poetry.org/). After cloning the project and moving into it, run:
```bash
# Install dependencies
poetry install --only main
# Initialize the database from the serialized data (only the first time)
poetry run ev json_import
```

You can now query the benchmark with the following methods. Examples are provided below; use `--help` to get the exact API.
```bash
# ev get_projects: get all the repository URLs in the benchmark
poetry run ev get_projects

# ev get_commits: get a list of commit hashes for which at least one vulnerability was published within the optional date range.
poetry run ev get_commits
# Filter by date
poetry run ev get_commits --after 2023-12-01
# More filtering
poetry run ev get_commits --after 2023-12-01 --before 2024-01-01 --project https://github.com/torvalds/linux

# ev get_by_commit: get a list of vulnerabilities present at a given commit
poetry run ev get_by_commit 54ecb8f7028c5eb3d740bb82b0f1d90f2df63c5c
# Filter by date
poetry run ev get_by_commit 54ecb8f7028c5eb3d740bb82b0f1d90f2df63c5c --after 2023-12-01
```

## Motivation
I believe that AI vulnerability detection in source code will disproportionately favor cyberdefense, especially if it is deployed on a wide scale as soon as it becomes feasible. The goal of this benchmark is to be a testing ground for new designs on this problem, as well as to keep evaluating the feasibility of wide-scale deployment as new models get released.

## How it works
To get into the details, Google's [osv.dev](https://osv.dev/) vulnerability database for open-source projects is used as input. Vulnerabilities are grouped by repository, and their affected versions are extracted. Finding the smallest set of commits that cover all the affected versions is an instance of the [hitting set problem](https://en.wikipedia.org/wiki/Set_cover_problem#Hitting_set_formulation). This is an NP-complete problem, but in practice Google's [CP-SAT](https://or-tools.github.io/docs/pdoc/ortools/sat/python/cp_model.html) solver handles it well in all the repos tested so far. Repository total sizes and language breakdowns are computed at each found commit using Github's [linguist](https://github.com/github-linguist/linguist), enabling filtering by repository size or language in downstream evaluations.
