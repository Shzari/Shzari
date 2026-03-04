# Refactor Regression Checklist

Date: 2026-03-04

## Baseline

- [ ] `flask routes` output captured from `run.py`
- [ ] App boots with `python run.py`
- [ ] App boots with `python app.py` (compatibility wrapper)

## Smoke Scenarios

- [ ] Login works for: `senior`, `junior`, `sysadmin`, `helpdesk`
- [ ] Net Devices:
  - [ ] senior manual command run works
  - [ ] junior pre-configured command run works
- [ ] HelpDesk Action:
  - [ ] Show Err-disable returns interfaces table
- [ ] Monitoring:
  - [ ] Monitoring panel opens
  - [ ] Node dashboard endpoint returns data
- [ ] IP Addressing:
  - [ ] Branch list loads
  - [ ] Add/Edit/Delete branch flow works

## Regression Checks

- [ ] Endpoint URLs are unchanged
- [ ] Session keys unchanged (`creds`, `auth_mode`, `buttons`, etc.)
- [ ] SQL connection and DB wrapper errors still handled consistently
- [ ] Template variable contracts unchanged (`buttons`, `manage_buttons`, etc.)
