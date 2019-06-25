set +x
# enable ssl to use these env variables
#OPTS="PYCIRCULATE_CERT=~/workspace/certs/cert.pem \
#    PYCIRCULATE_KEY=~/workspace/certs/key.pem \
#    PYCIRCULATE_USERNAME=\"adam\" \
#    PYCIRCULATE_PASSWORD=\"melissa\""

# comment to enable ssl & http auth
#OPTS=

echo "OPTS: [${OPTS}]"
PYTHONPATH=~/workspace/pycirculate/ python examples/rest/rest.py
