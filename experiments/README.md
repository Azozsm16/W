# Experiment log

Weight and threshold tuning records, per spec 13.2. Empty until **Sprint 6** -
tuning needs the attack data produced in Sprint 5.

Each run recorded here must state: the grid searched, the objective
(F-beta, beta = 0.5), the alerts/host/day figure for each combination, which
combinations the 5-alert constraint excluded, and the final frozen weights
with the date they were frozen.

Weights are frozen **before** the test set is touched. Adjusting them after
seeing test results invalidates the whole evaluation.
