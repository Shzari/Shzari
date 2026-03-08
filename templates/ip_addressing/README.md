IP Addressing Refactor (In Progress)

Current progress:
- Extracted ISP Branches panel to `templates/ip_addressing/panels/isp_branches_panel.html`
- Extracted ISP ATM-s panel to `templates/ip_addressing/panels/isp_atms_panel.html`
- Main page now includes both panels via `{% include %}` from `templates/ip_addressing.html`
- `templates/ip_addressing.html` now extends `templates/layouts/base.html`
- Added scaffold directories:
  - `templates/layouts/`
  - `templates/ip_addressing/components/`
  - `static/js/ip_addressing/`
  - `static/css/ip_addressing/`

Next steps:
1. Extract shared table header/toolbar into `templates/ip_addressing/components/`.
2. Move inline JS into feature files under `static/js/ip_addressing/`.
3. Move inline CSS into files under `static/css/ip_addressing/`.
4. Switch `ip_addressing.html` to `extends layouts/base.html`.
5. Split backend routes/repos by domain modules.
