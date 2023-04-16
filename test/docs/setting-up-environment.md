
# Pre requisites
**Make sure the following is installed on your box:**
- brew/linuxbrew
- Docker
- K3d
- Kubectl
- K9s

## Installing brew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

### Installing prereqs with brew
```
brew install k3d kubectl k9s
```

## Clone microservice example (sock shop)
git clone https://github.com/Havnevej/sockshop-speciale.git

# Create k3s cluster with 1 agent and 1 server (light cluster)
sudo k3d cluster create sockshop --agents 1 --servers 1

# Apply the sock shop to the cluster
sudo kubectl apply -f microservices-demo/deploy/kubernetes/complete-demo.yaml
*This will deploy the sockshop demo application and the vulnerable deployments that was introduced in this demonstration*

# Setting up the k3d environment
We use k3d to setup a demo kubernetes cluster using docker, with the speciale forked version of the microservice-demo application from Weaveworks.

# Using k9s
K9s is an interative command line GUI for a kubernetes cluster. Using: ":" colon you can specify which resources you want to view and specifying namespaces lets you choose a namespace with <enter> to only view further resources in this namespace


## Port forwarding the vulnerable python deployment
Using k9s
- Launch k9s: sudo k9s
You should see the interactive K9s GUI
----
*:* namespaces <enter>
> highlight sockshop namespace <enter>
*:* deployments <enter>
> highlight vulnerable python <enter>
* Now you are viewing the pods in this deployment, it should only show 1 pod
*Shift+F* <enter> <enter> 
----
Now you should have portforwarded the vulnerable deployment on the default port <5000> to your local machine
Check by going to a browser and opening localhost:5000, you should see "welcome to my page"
