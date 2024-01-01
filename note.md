# crea un ambiente virtuale
python3 -m venv venv
# attiva l'ambiente virtuale
source venv/bin/activate
# disattiva l'ambiente virtuale
deactivate
# per creare una lista delle dipendenze (!attiva venv)
pip freeze > requirements.txt
# per reinstallare le dipendenze
pip install -r requirements.txt
# kill ports (e.g using port 5000)
lsof -i :5000
"give u the 5000 port listener/s"
"read PID/s to kill (e.g. PID 18406)"
kill 18406
"use kill -9 to 18406 to force"


### qualche comando per il db
db.connect()
db.drop_tables([User])
db.create_tables([User])

### install
pythonanywhere
bash
git clone
create venv
activate venv
dependencies with requirements.txt
python3 app.py OR app.run(debug=True, port=8080) if port used by another

nano app.py
ctrl+o and enter to save
ctrl+x to exit

