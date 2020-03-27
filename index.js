const uuid = require("uuid");
const { Keystone } = require("@keystonejs/keystone");
const { GraphQLApp } = require("@keystonejs/app-graphql");
const { AdminUIApp } = require("@keystonejs/app-admin-ui");
const { KnexAdapter: Adapter } = require("@keystonejs/adapter-knex");
const {
  Checkbox,
  Text,
  Password,
  Select,
  Uuid
} = require("@keystonejs/fields");
const { PasswordAuthStrategy } = require("@keystonejs/auth-password");

const PROJECT_NAME = "Bottomline";

const keystone = new Keystone({
  name: PROJECT_NAME,
  adapter: new Adapter({
    knexOptions: {
      client: "postgres",
      connection: process.env.DATABASE_URL
    }
  }),
  onConnect: async keystone => {
    await keystone.createItems({
      User: [
        {
          id: uuid.v4(),
          name: "admin",
          email: process.env.ADMIN_EMAIL,
          state: "active",
          isAdmin: true,
          password: process.env.ADMIN_PASSWORD
        }
      ]
    });
  }
});
keystone.createList("User", {
  access: {
    // 1. Only admins can read deactivated user accounts
    read: ({ authentication: { item } }) => {
      if (item.isAdmin) {
        return {}; // Don't filter any items for admins
      }
      // Approximately; users.filter(user => user.state !== 'deactivated');
      return {
        state_not: "deactivated"
      };
    }
  },
  fields: {
    id: {
      type: Uuid,
      defaultValue: uuid.v4(),
      isRequired: true
    },
    name: { type: Text, isRequired: true },
    state: {
      type: Select,
      isRequired: true,
      options: ["active", "deactivated"],
      defaultValue: "active"
    },
    isAdmin: { type: Checkbox, defaultValue: false, isRequired: true },
    email: {
      type: Text,
      isUnique: true,
      isRequired: true,
      // 2. Only authenticated users can read/update their own email, not any other user's.
      // Admins can read/update anyone's email.
      access: ({ existingItem, authentication: { item } }) => {
        return item.isAdmin || existingItem.id === item.id;
      }
    },
    password: {
      type: Password,
      isRequired: true,
      access: {
        // 3. Only admins can see if a password is set. No-one can read their own or other user's passwords.
        read: ({ authentication }) => authentication.item.isAdmin,
        // 4. Only authenticated users can update their own password. Admins can update anyone's password.
        update: ({ existingItem, authentication: { item } }) => {
          return item.isAdmin || existingItem.id === item.id;
        }
      }
    }
  }
});

const authStrategy = keystone.createAuthStrategy({
  type: PasswordAuthStrategy,
  list: "User",
  config: {
    identityField: "email",
    secretField: "password"
  }
});

module.exports = {
  keystone,
  apps: [
    new GraphQLApp(),
    new AdminUIApp({ enableDefaultRoute: true, authStrategy })
  ]
};
