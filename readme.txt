python -m venv qnetvenv
qnetvenv\Scripts\activate


pip install -r requirements.txt

change password and username in settings.py file


python manage.py makemigrations
python manage.py migrate

python manage.py createsuperuser


python manage.py loaddata initial_data.json


python manage.py populate_defense_data


python manage.py runserver



