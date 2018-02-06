#!/usr/bin/env bash
# install serverless locally
echo "Installing a local version of serverless..."
npm install serverless
npm install serverless-python-requirements
npm install serverless-offline
# npm installs binary files to node_modules/.bin
echo
echo "Copying npm's bin directory up."
ln -s node_modules/.bin bin
# setup virtualenv for python requirements
echo
echo "Setting up a python virtual environment"
virtualenv . -p python3.6
echo
cat << __END__

To activate:

$ source bin/activate



__END__
