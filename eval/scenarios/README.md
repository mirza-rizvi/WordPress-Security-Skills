# Security scenario contracts

Each JSON file supplies a realistic task (`query`), the skills to load (`skills`),
expected review or implementation steps (`expected_behavior`), and observable
acceptance criteria (`success_criteria`). `name` is the scenario title.

These are evaluation prompts and rubrics, not executable vulnerability tests. The
repository validator checks their JSON structure, referenced skill names, and skill
coverage. A passing validator does not mean an agent solved the scenarios or that
resulting WordPress code is secure.

## Run a scenario manually

1. Prepare an isolated local WordPress project containing the described code path.
   Record the WordPress/PHP versions, skill revision, agent and model.
2. Load the listed skills and submit the query. Do not provide the expected answer
   as part of the query.
3. Compare the resulting change or report with the acceptance criteria. Equivalent
   secure implementations count; do not require incidental formatting or one exact
   helper when another preserves the same contract.
4. Exercise the changed path with authorized, unauthorized, and malformed requests.
   Record observed results and limitations separately from code-review conclusions.
5. Keep credentials and production data out of fixtures and result reports.

Do not label a scenario as passed without executing and recording that evaluation.
A schema-valid scenario is only a reviewed candidate for evaluation.

## Add a scenario

Use the existing JSON fields, with nonempty strings and arrays. Reference installed
skill names without duplicates; the router is listed once, including in its own
scenario. Choose one concrete failure mode and include both rejection behavior and
preserved legitimate behavior in the rubric. State prerequisites rather than
assuming a vulnerability is exploitable or assigning severity in advance.
