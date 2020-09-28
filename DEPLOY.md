rm -rf venv
python3.8 -m venv venv
source venv/bin/activate
python -m pip install -U -r requirements.txt
rm -rf dist/
python setup.py sdist bdist_wheel
twine check dist/*
twine upload dist/*
