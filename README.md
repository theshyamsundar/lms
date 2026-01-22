
# LearningStat Enterprise Demo (Working Model)

This is a **working demo platform** that brings your “vibe-coded LearningStat” concept into a more **standardised, enterprise-grade** workflow:

✅ Multi-tenant data model (org_id everywhere)  
✅ Role-based access (RBAC)  
✅ Learner engagement (gamification: points, streaks, badges, leaderboard)  
✅ Manager enablement (team dashboards, nudges, behaviour observations)  
✅ L&D analytics (program analytics: completion funnel, assessments, surveys, KPI trend)  
✅ ROI workspace (cost + benefit model, scenarios, finance approvals)  
✅ Audit log + notifications (basic governance patterns)

> This demo is intentionally lightweight (Flask + SQLite), but the architecture is designed so you can extend it into a production platform.

---

## Quick start

### 1) Install dependencies

```bash
pip install -r requirements.txt
```

### 2) Run the app

```bash
python app.py
```

Open:

- http://127.0.0.1:5000

The app auto-creates and seeds the database on first run:
- `learningstat_demo.sqlite3`

Org slugs in this seed:
- `abc-private-limited`
- `learningstat-platform`

---

## Demo organisation: ABC Private Limited

### Demo logins

- Platform Admin: `platform@learningstat.com` / `Admin123!`
- Org Admin: `admin@abc.com` / `Admin123!`
- L&D Admin: `ld_admin@abc.com` / `Demo123!`
- L&D Analyst: `analyst@abc.com` / `Demo123!`
- Finance: `finance@abc.com` / `Demo123!`
- Manager (Sales): `manager_sales@abc.com` / `Demo123!`
- Executive: `exec@abc.com` / `Demo123!`
- Learner: `learner_sales_01@abc.com` / `Demo123!`

---

## Suggested “feedback testing loop” (manual)

Use this loop to validate the end-to-end workflow is smooth:

1) Login as a learner
   - Go to **My Learning**
   - Open a course
   - **Mark complete**
   - Take **POST assessment**
   - Submit **Reaction** + **Confidence** surveys
   - Check points/streak/badges on **Profile**

2) Login as Manager
   - Check **At-risk learners**
   - Send **Nudges**
   - Submit **Behaviour observations**

3) Login as L&D Admin/Analyst
   - Open **Program analytics**
   - Verify completion funnel changed
   - Verify assessment averages changed
   - Verify behaviour observation average appears
   - Go to **ROI workspace**
     - Add costs/benefits if needed
     - Switch scenarios

4) Login as Finance
   - Go to **Finance dashboard**
   - Approve draft cost lines in ROI workspace
   - (Now ROI % becomes available)

5) Login as Executive
   - Confirm the **ROI by program chart** and the ROI table shows updates

---

## Extending this into an enterprise platform

This demo is a working foundation. To reach an enterprise-grade build, typical upgrades include:

- SSO (SAML/OIDC) + MFA policy enforcement
- SCIM provisioning/deprovisioning
- Row-level security hardening (DB-enforced policies)
- Full audit trail + immutable event log
- Data ingestion connectors (LMS/LXP/HRIS/CRM) + xAPI/LRS support
- Dedicated analytics warehouse + semantic layer
- Approvals workflow for ROI assumptions & unit-cost sources
- Custom report builder + scheduled exports + governance controls

---

## Files

- `app.py` — main Flask app (routes, DB schema, seed data, RBAC, ROI logic)
- `templates/` — UI templates
- `static/` — minimal styling
- `learningstat_demo.sqlite3` — created on first run

---

## Notes

- This is a **demo**, not a hardened security product.
- Passwords are hashed. Sessions use Flask cookies. Change `LEARNINGSTAT_SECRET_KEY` for real deployments.


---

## Multi-tenant demo (optional)

Login as **Platform Admin**:

- `platform@learningstat.com` / `Admin123!`

Then go to:

- Platform → **Create organisation**

This creates a new tenant (org) + an initial **ORG_ADMIN** user, so you can validate the platform supports different organisation requests.
