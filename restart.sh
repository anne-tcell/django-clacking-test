cd ~/git-projects/jsagent-tcell
grunt
cp dist/tcellagent.debug.js ~/git-projects/django-clacking-test/fakesite/pages/tcellagent.debug.js
cd ~/git-projects/django-clacking-test
source venv/bin/activate
echo "~~~ to test on mac, open localhost:8000 ~~~"
echo "~~~ to test on windows vm, open http://10.0.2.2:8000 ~~~~"
./venv/bin/tcell_agent run python manage.py runserver

