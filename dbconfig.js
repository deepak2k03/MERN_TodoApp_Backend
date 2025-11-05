import { MongoClient } from "mongodb";
import dotenv from "dotenv";
dotenv.config();

const url = process.env.MONGO_URI;
const dbNmae = process.env.DB_NAME || "MERN_Todo_App";
export const collectionName = "todo";
const client = new MongoClient(url);

export const connection = async () => {
  const connect = await client.connect();
  return await connect.db(dbNmae);
};
