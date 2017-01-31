# swift-http-auth installation instructions
apt-get install python3-requests python3-awsauth
git clone -b python3 https://github.com/honza801/rgwadmin /opt/rgwadmin
ln -s /opt/swift-http-auth/swift-http-auth.service /etc/systemd/system/
