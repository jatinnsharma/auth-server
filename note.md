# Status Code

400 - bad request
201 - created 



# Generate Token

- create arrow function
- have id parameter because we're going to use the id of use to generate token
- create JWT_SECRET in .env file.
for example
------------
const generateToken =(id) =>{
    return jwt.sign(
        {id},
        process.env.JWT_SECRET,
        {expiresIn:'1d' }
    )
};


# Register User

- When we want to register a user , what's the first thing we do?
- we need some credentials from that user credentials being the name , the email and the password. destructed it out from req.body
- validation
  - what if those information are not send from the request/frontend
  - if(!name || !email || !password ) return error and message;
- check if user exists - find in the database
- if the user does not exist ? then register the user.
  - create new user
- when create the new log that user in immediately
- how to log that use
- we are going to generate a token , a JSON web token and then send that token along with cookies
- res.cookie(name,sendgeneratetoken(token),object)
- if user is actually create then send response to frontend if not created and throw error 
- user agent - either user browser or the user device.
- we going to capture that when the user signs up.
- because we're able to capture that, if the user try to log in from another device , we can tigger as two factor authentication. 
- npm i ua-parser-js


# login 
### get data form req.body 
### check validation 
### check user actually exist in database.
### if user doesn't exist then show message(User not found , please signup)
### check password is correct or not compare by using bcrypt
### if password is not correct show error(Invalid email or password)
### Trigger 2FA for unknow UserAgent
### login the user if email and password by sending jwt token in their cookies  
### send some user data in the res


# logout 
### if expire the cookie or delete the cookie , then user is logged out.


# Get User 
#### when you want to get a user , you dont want this route to be accessible to just anybody
### user should only be able to get their own data.
### should not able to get other user data information.
### admin or who have right should be able to get the user data.
### create middleware that product our routes. 

## auth middleware 
#### get user cookie 
#### what if there is no token response error (Not authorized, please login)
#### verify jwt token 
```bash 
cosnt verified - jwt.verify(token,proccess.env.JWT_SECRET)
``` 
#### get user id from token
#### dont send user password - select("-password")
#### if no user found send response user not found 
#### if user is suspended he/she no able to get user data 
#### if everything is fine 



# update user 
#### Get user infomation from database.
#### check user is present or not if user is not found show error 
#### else update the user dont update email of the user 
#### after update sent response back to user 


# send email verification
#### getting the user from database
#### check user is exited or not 
#### check if user already verified.
#### if not verified , Delete token if it exists in DB 
#### create verification token 
#### hash token and save 
#### Construct Verification URL 
#### send email


# forgot password 
#### getting the user from database
#### check user is exited or not 
#### Delete token if it exists in DB 
#### create Reset token  
#### Construct Reset URl 
#### send email 

# T2F
#### check user which device to login with is this user 
#### registered in our database
#### if user is not in our database trigger two factor authentication.
#### generate 6 digit code 
#### encrytped login code and save in db.
