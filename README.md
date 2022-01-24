# AltRantNotificationServer
A notification server for the AltRant project.
# How Does This Server Work?
This server is a **local** server, meaning that no sensitive data ever exits the local machine and no data goes to me. The only data that goes out are secure requests to the devRant API servers to retrieve notification data and check for new stuff, and a request to the OneSignal notification services. I am not using the vanilla Apple Push Notification Services (APNs), because that would make me distribute my private APN certificate, an act that violates the Apple Developer code-of-conduct. The server is open-source (as you can clearly see), so you can read through the entire code if you'd like and make a decision to whether you'd like to use this server with AltRant and receive notifications or not.

## Note to dfox:
If you would like this to not exist or be supported in the AltRant project, **please contact me by email, by a devRant comment on [this post](https://devrant.com/rants/5070459/i-havent-said-anything-yet-but-an-altrant-notification-server-exists-support-for) or by GitHub issue here.** I will comply with your request to take it down if you please. After all, it is your platform and your choice.
# How to Use
Clone this repository: 

`git clone https://github.com/OmerFlame/AltRantNotificationServer.git`

Install the dependencies:

`pip3 install flask Crypto` 

And then run the script:

`python3 main.py`
