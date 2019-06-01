# enable ssl to use these env variables
PYCIRCULATE_CERT=~/workspace/certs/cert.pem \
    PYCIRCULATE_KEY=~/workspace/certs/key.pem \
    PYCIRCULATE_USERNAME="adam" \
    PYCIRCULATE_PASSWORD="melissa" \
    PYTHONPATH=~/workspace/pycirculate/ python examples/rest/rest.py
