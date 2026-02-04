import { Schema, model } from 'mongoose';

const expSchema = new Schema({
  title: { type: String, required: true },
  organization: { type: String, required: true },
  description: { type: String },
  period: { type: String }
});

export const Experience = model('Experience', expSchema);