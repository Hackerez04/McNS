# ABOUT

Powerful Minecraft name sniper in python. It supports different kind of method/type of account.
- Normal accounts
- Accounts with no name assigned
- Multiple names to sniper per account

It supports token authentication and Microsoft authentication.
You don't need to provide a token because it will automatically take it.

# NOTE!
### Remember to remove the 2fa otherwise the program will not be able to send requests using the Microsoft authentication.
### If you don't want to disable 2fa, you can't use Microsoft auth so you have to provide manually the token for each account and update it manually every 24h.

# Instructions 
![Alt text](screenshot.jpg?raw=true "Screenshot")

1. Edit the .json file and add as many account you want.
2. Edit the .py file in the main func. using the method that you need:
   - If you use only 1 account with 1 name uncomment and edit `single_name("","","")` and put your data in this order: "email", "password", "name_to_snipe"
   - If you want to use multiple accounts edit the line with `multi_name_list = []` and put the email of the accounts that you want to use.
   - If you want to use accounts that don't have a name registered  edit the line with `no_name_list = []` and put the email of the accounts that you want to use.
3. Run the program

# EXAMPLE
### JSON
```
{
    "account": [
      {
        "token": "",
        "email": "your@email",
        "password": "your_password",
        "name-list": [
          {
            "name": "name_to_snipe"
          },
          {
            "name": "another name..."
          },
          {
            "name": "put how many u want..."
          }
        ]
      },
      {
        "token": "",
        "email": "ez_email@email.com",
        "password": "your_password",
        "name-list": [
          {
            "name": "name_to_snipe"
          },
          {
            "name": "stonks_name"
          }
        ]
      },
      {
        "token": "",
        "email": "super@email",
        "password": "superpassword",
        "name-list": [
          {
            "name": "stonks_name"
          },
          {
            "name": "snipe"
          },
          {
            "name": "cool"
          }
        ]
      }
    ]
  }
```
## PYTHON
```
multi_name_list = ["your@email","ez_email@email.com"]

no_name_list = ["super@email"]
```

# INSTALLATION
1. `git clone https://github.com/Hackerez04/McNS.git`
2. `cd McNS`
3. `pip install -r requirements.txt`

### It's time to snipe some names!
