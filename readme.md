# Make it executable:
chmod 755 Web/SecurityCheck/securityscan

# 2 Run it:
./securityscan foldername

# Aavailable everywhere, move/link it into your $PATH:
sudo ln -s ~/Web/SecurityCheck/securityscan /usr/local/bin/securityscan
# Then run from anywhere:
securityscan foldername

# Optional rebuild
./securityscan foldername --rebuild

# Docker rebuild
docker build --no-cache -t wp-offline-scanner .