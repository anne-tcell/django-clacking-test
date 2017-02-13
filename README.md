# Clickjacking demo

This is a Django app to demo clickjacking.

## Install

0. Install Python 3.6. Other versions probably work too.
1. `git clone [repo]`
2. `cd django-clacking-test`
3. `pip install -r requirements.txt`
4. Create an app on `cd4.tcell-preview.io` (<b>Admin > Applications</b>).
5. Go to <b>Admin > Download Agent > Server Agent</b>, download a config file, and place it in the root directory of `django-clacking-test`.
6. Copy `fakesite/pages/clickjack-target.template.html` as `fakesite/pages/clickjack-target.html`.
7. Go to <b>Admin > Download Agent > Javascript Agent</b>, generate a key, and paste the script into `fakesite/pages/clickjack-target.html`.
8. `tcell_agent run python manage.py runserver`
9. Navigate to `localhost:8000`.

Modify clickjacking settings on the tCell dashboard at <b>Settings > Policies > Clickjacking</b>.
