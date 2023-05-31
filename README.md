
# Installing brew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Clone microservice example (sock shop)
git clone https://github.com/microservices-demo/microservices-demo.git

# Create k3s cluster with 3 agents and 3 servers
sudo k3d cluster create sockshop --agents 3 --servers 3

# Apply the sock shop to the cluster
sudo kubectl apply -f microservices-demo/deploy/kubernetes/complete-demo.yaml