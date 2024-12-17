# AWSServerIsolate

AWS Incident Response Tool

The following project is an AWS Python IR Project that will help Cloud teams to isolate Individual
AWS EC2 Servers while removing the EC2 Server Public IP Address, Security Groups,
and IAM Instance role for further investigation.

Feel to free to use and give any feedback. Thank you.

### Installation



### Usage

```
python3 isolate.py --help
usage: isolate.py [-h] [--instance INSTANCEID] [--region REGION] [--profile PROFILE]

AWS isolate EC2 Server. Input EC2 instance ID for server and region.

options:
  -h, --help           show this help message and exit
  --instance INSTANCE  AWS EC2 Server Instance ID
  --region REGION      AWS EC2 Server Region
  --profile PROFILE    AWS profile name
```

### License

Copyright (C) Gregory Fuentes (gregoryfuentes80@gmail.com)

License: GNU General Public License, version 2

