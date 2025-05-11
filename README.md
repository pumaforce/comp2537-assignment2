# comp2537-assignment2#
## Setup git

git log --show-signature
git branch -M main
git remove add origin https://github.com/pumaforce/comp2537-assignment1.git/
git commit -m "first commit"

git push -u origin main

## Setup Node project and Express, express-session

````bash
npm init -y
npm i express
npm i nodemon
npm i express-session 
need to use a previous version of express
"express": "^4.18.2",
npm i dotenv
npm i joi
npm i connect-mongo

npm run devStart

#other helpful tricks

killall -9 node  // reset port 3000 by killing all node.

#Demo
use [$ne] on the user name