const express = require('express')
const app = express()
const dotenv = require("dotenv");
dotenv.config();
const port = process.env.port || 5000
const mongoDB = require("./db")

app.use((req,res,next)=>{
  res.setHeader("Access-Control-Allow-Origin","http://localhost:3000","https://delo-backend.onrender.com");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-Width, Content-Type, Accept"
  );
  next();
})

mongoDB();
app.get('/', (req, res) => {
  res.send('Hello World!')
})
app.use(express.json()) //middleware
app.use('/api', require("./Routes/CreateUser"));
app.use('/api', require("./Routes/DisplayData"));
app.use('/api', require("./Routes/OrderData"));
app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})
