Set up:
1. Create *.verified.example.com pointing to the TEE

From inside a TEE:
1. Generate a TLS private/public key pair 
2. Calculate pubH = hash(pubK)
3. Retrieve Att = attest(pubH)
4. Calculate AttH = hash(att)
5. Use LetsEncrypt to create cert(verified.example.com, $AttH.verified.example.com). Can use HTTP challenge for this!

CT Verification:
1. Watch CT logs for verified.example.com
2. Check that every cert also has $AttH.verified.example.com in it 
3. Use $AttH to retrieve the attestation from content-addressable storage 
4. Get $Attestation.Data to get pubH
5. Assert that pubH matches cert 
6. Assert that there are no other certs that match (i.e. no *.example.com or *.verified.example.com)

Client verification (removes CT dependency):
1. Hook into cert validation inside of a client (e.g. in firefox extension or in a non-browser client)
2. Perform above steps 

Ideal API:
* Golang binary. Run it at startup of a TEE and it provisions a cert before the main program is started. Main program can then just run with the cert.

--- 

 ```
aws ec2 create-security-group --group-name "launch-wizard-2" --description "launch-wizard-2 created 2025-04-10T23:11:38.745Z" --vpc-id "vpc-0a6e786e59e628587" 
aws ec2 authorize-security-group-ingress --group-id "sg-preview-2" --ip-permissions '{"IpProtocol":"tcp","FromPort":22,"ToPort":22,"IpRanges":[{"CidrIp":"0.0.0.0/0"}]}' '{"IpProtocol":"tcp","FromPort":443,"ToPort":443,"IpRanges":[{"CidrIp":"0.0.0.0/0"}]}' '{"IpProtocol":"tcp","FromPort":80,"ToPort":80,"IpRanges":[{"CidrIp":"0.0.0.0/0"}]}' 
aws ec2 run-instances --image-id "ami-0515da4bec0819859" --instance-type "c7g.large" --key-name "m1" --block-device-mappings '{"DeviceName":"/dev/xvda","Ebs":{"Encrypted":false,"DeleteOnTermination":true,"Iops":3000,"SnapshotId":"snap-0eb85e009b6f0aabf","VolumeSize":20,"VolumeType":"gp3","Throughput":125}}' --network-interfaces '{"AssociatePublicIpAddress":true,"DeviceIndex":0,"Groups":["sg-preview-2"]}' --tag-specifications '{"ResourceType":"instance","Tags":[{"Key":"Name","Value":"nitro2"}]}' --metadata-options '{"HttpEndpoint":"enabled","HttpPutResponseHopLimit":2,"HttpTokens":"required"}' --private-dns-name-options '{"HostnameType":"ip-name","EnableResourceNameDnsARecord":true,"EnableResourceNameDnsAAAARecord":false}' --count "1" 

ssh ec2-user@verified-dev.daviddworken.com

scp ~/code/teels-keys/id_ed25519.pub ec2-user@15.207.221.31:/home/ec2-user/.ssh/
scp ~/code/teels-keys/id_ed25519 ec2-user@15.207.221.31:/home/ec2-user/.ssh/

# On the machine:
sudo yum install -y docker git go socat htop
sudo service docker start
sudo usermod -a -G docker ec2-user
sudo dnf install aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel -y
sudo usermod -aG ne ec2-user
git clone git@github.com:ddworken/teels.git
git config --global user.name "David Dworken"
git config --global user.email "david@daviddworken.com"
curl https://hishtory.dev/install.py | python3 -

#sudo dd if=/dev/zero of=/swapfile bs=1M count=1024
#chmod 0600 /swapfile
#sudo mkswap /swapfile
#sudo swapon /swapfile

# Logout and then log back in
sudo nano /etc/nitro_enclaves/allocator.yaml # configure 1 CPU and memory limit 
sudo systemctl enable --now nitro-enclaves-allocator.service
 ```