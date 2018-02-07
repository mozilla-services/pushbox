# install serverless locally
echo npm install serverless
# npm installs binary files to node_modules/.bin
echo ln -s node_modules/.bin bin
# setup virtualenv for python requirements
echo virtualenv .
cat << __END__

To activate:

$ source bin/activate

You may wish to consider running the "offline" plugin

$ npm install serverless-offline

__END__
