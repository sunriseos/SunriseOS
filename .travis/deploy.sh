# Decrypt and setup the deploy key.
openssl aes-256-cbc -K $encrypted_a3c22127997a_key -iv $encrypted_a3c22127997a_iv -in .travis/github_deploy_key.enc -out .travis/github_deploy_key -d
eval "$(ssh-agent)"
chmod 600 .travis/github_deploy_key
ssh-add .travis/github_deploy_key

# Deploy!
cargo make deploy-doc
