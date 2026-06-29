const { MongoClient } = require("mongodb");

const uri = "MONGO_URI=mongodb://gururaj:women1234@ac-hodp7xv-shard-00-00.3bhehsl.mongodb.net:27017,ac-hodp7xv-shard-00-01.3bhehsl.mongodb.net:27017,ac-hodp7xv-shard-00-02.3bhehsl.mongodb.net:27017/women?ssl=true&replicaSet=atlas-1321hq-shard-0&authSource=admin&retryWrites=true&w=majority";

const client = new MongoClient(uri);

async function run() {
  try {
    await client.connect();
    console.log("Connected successfully");
  } catch (err) {
    console.log(err);
  }
}

run();