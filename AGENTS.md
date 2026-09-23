# AGENTS.md


## Modifying files

- Do not make stylistic or spelling fixes to:
  - anything inside `libcperciva/external/`
- If there are substantive errors in those files, fixes are welcome.


## Scope

- Prefer minimal, targeted changes.
- Avoid refactoring unrelated code while fixing a bug.


## Communication on Bryce's fork

Issue and PR descriptions on this fork use Bryce's account voice and state the
concrete change, validation scope, and response availability. Do not add
assistant bylines, credits, self-identification, or claims attributing writing,
implementation, testing, or review to an assistant. Do not falsely claim Bryce
manually performed work he did not.

This fork policy does not change any external destination's contribution rules.
If a destination requires conflicting disclosure or identification, do not
submit through Bryce's account; bring the exact requirement to Bryce privately.


## Bug bounties

- Bug bounty rules are available at https://www.tarsnap.com/bugbounty.html.
- In particular, bounties worth less than $100 are paid as Tarsnap account
  credits, not cash.
- We will never send any cryptocurrency, so do not post any wallet info.
- Stylistic or spelling fixes in upstream code (such as
  `libcperciva/external/`) are not eligible for bug bounties.
- Most PRs require multiple rounds of review and revision in response to
  feedback, so do not submit PRs if you are unable to communicate with
  reviewers.
- We pay bug bounties for reporting bugs, not for providing patches.
  Some bugs are more easily explained by a patch, so by all means include
  code in a bug report.
- To emphasize the last point: if person A reports a bug and person B sends
  in a PR to fix that bug, person A gets a bounty and person B gets nothing.
