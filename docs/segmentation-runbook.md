# Segmentation review runbook

A quarterly review with the plant manager, the OT engineer and IT, plus a short check after every vendor visit.

## Before the review (IT)

1. Export the OT firewall rules to `conduits.csv`, with the purpose and approver of each one.
2. Export one week of flows that covers every shift and at least one product changeover.
3. Refresh `assets.csv` from the inventory; add anything new on the line networks.
4. Run `python -m otseg report data/ --out output/` and send `review.md` a day before.

## In the review (60 minutes)

1. **Fix first** (`report.html`): agree an owner and a date for each critical line.
2. **Proposed conduits**: go through every `block`, `re-route via DMZ` and `review` row. The plant decides what the process needs; IT decides how it travels.
3. **Temporary rules**: close the expired ones and confirm end dates for the rest.
4. **End-of-life systems**: confirm the compensating controls and the replacement date.

## After the review

- Change the firewall through the normal change process, one zone at a time, outside production hours, with a rollback plan.
- Re-run the report the day after each change: the flow must move from `review` to `allow`, or disappear.
- Keep `actions.csv` as the follow-up list until the next review.

## After a vendor visit

- Remove the temporary rule, check that the vendor's sessions came through the jump host, and re-run the report.
