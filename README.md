# eyeballvul

eyeballvul is an open-source benchmark designed to enable the evaluation of [SAST](https://en.wikipedia.org/wiki/Static_application_security_testing) vulnerability detection tools, especially ones based on language models, designed to be future-proof.

While most benchmarks eventually make it into the training data of language models, eyeballvul is designed to be continuously updated from the data source of CVEs in open-source repositories. This means that it will remain relevant as long as models have a reasonably delayed training data cutoff, by evaluating on the subset of the vulnerabilities that were published after the training data cutoff of the considered model. The current goal is to update it weekly.

At a high level, eyeballvul converts the data stream of CVEs in open-source repositories into a small set of commits for each repository, and a set of vulnerabilities present at each of these commits.

The typical use case that this benchmark enables is the following:
1. select a list of repositories and commits for which there is at least one vulnerability published after some date;
1. run a SAST tool (typically LLM-based) on the source code at each of these commits;
1. compare the results of the SAST tool with the list of known vulnerabilities for each commit, especially the ones that were published after the training data cutoff.

eyeballvul currently contains 28,158 vulnerabilities, in 7,433 commits and 6,441 repositories.

The data can be seen in the `data` directory. There are two kinds of items: **vulnerabilities** and **revisions**. A vulnerability corresponds to an entry in the [osv.dev](https://osv.dev/) database (typically a CVE), and may be present at multiple revisions of the repository. A revision represents the state of a repository at a given commit, and may be associated with multiple vulnerabilities. Let's look at an example of each (commands explained in the [How to use](#how-to-use) section):
```bash
# Vulnerability:
poetry run ev get_by_project https://github.com/gnome/nautilus --after 2019-01-01 --before 2020-01-01
```
Output:
```
[
  {
    "id": "CVE-2019-11461",
    "published": "2019-04-22T21:29:00",
    "modified": "2023-11-29T06:57:11.439677",
    "details": "An issue was discovered in GNOME Nautilus 3.30 prior to 3.30.6 and 3.32 prior to 3.32.1. A compromised thumbnailer may escape the bubblewrap sandbox used to confine thumbnailers by using the TIOCSTI ioctl to push characters into the input buffer of the thumbnailer's controlling terminal, allowing an attacker to escape the sandbox if the thumbnailer has a controlling terminal. This is due to improper filtering of the TIOCSTI ioctl on 64-bit systems, similar to CVE-2019-10063.",
    "severity": [
      {
        "type": "CVSS_V3",
        "score": "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H"
      }
    ],
    "repo_url": "https://github.com/gnome/nautilus",
    "cwes": [],
    "commits": [
      "a241f8f6f37220ccec78a40b015967188490b1df"
    ]
  }
]
```

```bash
# Revision:
poetry run ev get_revision a241f8f6f37220ccec78a40b015967188490b1df
```
Output:
```
{
  "commit": "a241f8f6f37220ccec78a40b015967188490b1df",
  "repo_url": "https://github.com/gnome/nautilus",
  "date": "2019-03-13T12:14:26",
  "languages": {
    "C": 4696806,
    "Meson": 29700,
    "Python": 7401,
    "Shell": 6020,
    "CSS": 5486
  },
  "size": 4745413
}
```


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
poetry run ev get_projects --count
# -> 6441

# ev get_commits: get a list of commit hashes for which at least one vulnerability was published within the optional date range.
poetry run ev get_commits --count
# -> 7433
# Filter by date
poetry run ev get_commits --after 2023-12-01
# More filtering
poetry run ev get_commits --after 2023-12-01 --before 2024-01-01 --project https://github.com/torvalds/linux
# -> [
# ->   "54ecb8f7028c5eb3d740bb82b0f1d90f2df63c5c",
# ->   ...
# -> ]

# ev get_revision: get the revision corresponding to a given commit
poetry run ev get_revision a241f8f6f37220ccec78a40b015967188490b1df
# -> <output already shown above>

# ev get_by_commit: get a list of vulnerabilities present at a given commit
poetry run ev get_by_commit 54ecb8f7028c5eb3d740bb82b0f1d90f2df63c5c
# -> [
# ->   {
# ->     "id": "CVE-2019-20636",
# ->     "published": "2020-04-08T14:15:12",
# ->     "modified": "2023-11-29T06:41:03.928053",
# ->     "details": "In the Linux kernel before 5.4.12, drivers/input/input.c has out-of-bounds writes via a crafted keycode table, as demonstrated by input_set_keycode, aka CID-cb222aed03d7.",
# ->     "severity": [
# ->       {
# ->         "type": "CVSS_V3",
# ->         "score": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
# ->       }
# ->     ],
# ->     "repo_url": "https://github.com/torvalds/linux",
# ->     "cwes": [],
# ->     "commits": [
# ->       "54ecb8f7028c5eb3d740bb82b0f1d90f2df63c5c",
# ->       "8fe28cb58bcb235034b64cbbb7550a8a43fd88be",
# ->       "c470abd4fde40ea6a0846a2beab642a578c0b8cd"
# ->     ]
# ->   },
# ->   ...
# -> ]

# Filter by vulnerability publication date, for a given commit
poetry run ev get_by_commit 54ecb8f7028c5eb3d740bb82b0f1d90f2df63c5c --count
# -> 67
poetry run ev get_by_commit 54ecb8f7028c5eb3d740bb82b0f1d90f2df63c5c --after 2024-01-01 --count
# -> 7
```

## Motivation
I believe that AI vulnerability detection in source code will disproportionately favor cyberdefense, especially if it is deployed on a wide scale as soon as it becomes feasible. The goal of this benchmark is to be a testing ground for new designs on this problem, as well as to keep evaluating the feasibility of wide-scale deployment as new models get released.

The name "eyeballvul" comes from Linus's law, the assertion that "given enough eyeballs, all bugs are shallow". eyeballvul will hopefully help with the deployment of large numbers of AI eyeballs, once they can see well enough.

By choosing an all-lowercase name for this project, I hope to reduce the friction of adoption from leading AI labs.

## How it works
To get into the details, Google's [osv.dev](https://osv.dev/) vulnerability database for open-source projects is used as input. Vulnerabilities are grouped by repository, and their affected versions are extracted. Finding the smallest set of commits that cover all the affected versions is an instance of the [hitting set problem](https://en.wikipedia.org/wiki/Set_cover_problem#Hitting_set_formulation). This is an NP-complete problem, but in practice Google's [CP-SAT](https://or-tools.github.io/docs/pdoc/ortools/sat/python/cp_model.html) solver handles it well in all the repos tested so far. First, the number of commits necessary to cover all the affected versions is minimized, then the sum of their dates is maximized (to get more recent commits, all other things equal). Repository total sizes and language breakdowns are computed at each commit using Github's [linguist](https://github.com/github-linguist/linguist), enabling filtering by repository size or language in downstream evaluations.
