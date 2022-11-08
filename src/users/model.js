import mongoose from "mongoose"
import bcrypt from "bcrypt"

const { Schema, model } = mongoose

const UsersSchema = new Schema(
  {
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true },
    password: { type: String, required: true },
    role: { type: String, enum: ["Admin", "User"], default: "User" },
  },
  { timestamps: true }
)

UsersSchema.pre("save", async function (next) {
  // BEFORE saving the user in db, executes a function (in this case hash the pw)
  // I am not using an arrow function here because of "this" (it would be undefined in case of arrow func)

  const currentUser = this
  if (currentUser.isModified("password")) {
    // only if the user is modifying the pw (or if the user is being created) I would like to use some CPU cycles to calculate the hash, otherwise they would be just wasted
    const plainPW = currentUser.password

    const hash = await bcrypt.hash(plainPW, 11)
    currentUser.password = hash
  }

  next()
})

UsersSchema.methods.toJSON = function () {
  // this .toJSON method is used EVERY TIME Express does a res.send
  // this does mean that we could override the default behaviour of this method to remove the pw (and other unnecessary things) from the user/s and then return them

  const userDocument = this
  const user = userDocument.toObject()

  delete user.password
  delete user.createdAt
  delete user.updatedAt
  delete user.__v

  return user
}

export default model("user", UsersSchema)
