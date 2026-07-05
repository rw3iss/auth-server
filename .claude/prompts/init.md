Can you create for me a standalone, tenant or organization-based authentication server, written in Go, that can handle registering new users, and authenticating them? Each user should be linked to a base user, registered at first with or without a given organization's details (using either a new organization's details, or an invitation code or token for a given organization). Users do not need to register with an organization, but they can if they want, or they can join an organization later (using the invite token or code approach).
A base user may be part of multiple organizations, and would therefore choose to login to any given organization during their login.
The token generated during login should be for the user->organization connection, if they have chosen to login through an organization.
Specific user tokens should be matched to specific roles for the organization, and each role will have given permissions to perform certain actions (ie. RBAC).

This is for an auction platform, if you need to know the domain subject matter.

Their will be a basic set of roles, which can be assigned to organizations, or not, such as:
- Super Administrators (these are internal users that only our company will use).
- Administrators (these are part of an organization, and can create and edit roles, and manage the role assignments to users, and the users themselves, among all other permissions below it).
- Managers (these can manage anything about the users and role assignments for them, but they cannot edit or remove roles themselves).
- Sellers (these have permissions to list or create new auctions, and edit them)
- Buyers (these are standard users which have permissions to register for auctions, and bid on items).

There will also be the ability for Administators and Managers to create custom roles that can be assigned to users, with the ability to choose custom permissions for them.

Users may be given multiple roles and permissions. For example, a user may be a Super Administrator, as well as a Seller. Or a user may only be a Seller and a Buyer. Generally administrative roles will have permissions to perform all actions anyway, but the system should support assigning multiple roles to users.

When a user is created or registered, it should assign the base user a given role, outside of an organization, but they should also be assigned to organization roles if they sign up through an organization token.
If a user logs in without an organization, it should still give them a basic user token with minimal base permissions for their basic role, but not for any given organization.
If a user logs in with an organization, it should generate the token that can work with any of the permissions for the roles assigned to the user through that organization.

Users should also be able to register using SSO with providers such as Google, Apple, and other common SSO providers, including possibly custom SSO providers (such as a third party API which we might have a contract with as a unique vendor or organization with our auction platform company).
Please ensure the module responsibilities are architected cleanly to support SSO alongside the traditional registration and organization associations.

The authentication server should include a well architected API for registering users (either plainly, with an organization, or through SSO, also possibly with an organization), logging the users in (plainly or through SSO and with or without an organization), authenticating tokens to verify users from different internal services, and also password and token management such as resetting passwords for users (and sending the appropriate emails), or revoking or refreshing tokens for users, if they need to. The login endpoints should support remembering users for a specified number of days. Also implement any other necessary endpoints for a versatile standalone authentication server for our company.

Can you use the most enterprise-level architecture to create this standaline authentication server, written in Go, that will be used by multiple frontend client applications for the many different organization users?

Please architect the code as cleanly and well organized as possible, using S.O.L.I.D. principles.

Any standardized models or classes that might be re-used on other parts of different applications (ie. some domain-level servers) should be extracted into their own shared package, for the auction platform. This could include the basic users and basic roles, and other shard classes.

If you see any issues with the above design for the versatile authentication server, then go ahead make the changes to implement it using best industry practices and enterprise standards, and note the design changes.

Please also design a UML diagram, and some explanation, of how the entire system works, in a readme file.