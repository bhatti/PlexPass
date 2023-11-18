# PlexPass
A Secured Family-friendly Password Manager

## Background
With the proliferation of online services and accounts, it has become almost impossible for users to remember unique and strong passwords for each of them. Some users use the same password across multiple accounts, which is risky because if one account is compromised, all other accounts are at risk. With increase of cyber threats such as [2022-Morgan-Stanley](https://techcrunch.com/2022/09/21/morgan-stanley-hard-drives-data-breach/), [2019-Facebook](https://www.wired.com/story/facebook-passwords-plaintext-change-yours/), [2018-MyFitnessPal](https://www.aafp.org/news/practice-professional-issues/20180403myfitnesspal.html), [2019-CapitalOne](https://www.capitalone.com/digital/facts2019/), more services demand stronger and more complex passwords, which are harder to remember. Standards like [FIDO](https://fidoalliance.org/what-is-fido/) (Fast IDentity Online), [WebAuthn](https://webauthn.guide/) (Web Authentication), and [Passkeys](https://fidoalliance.org/passkeys/) aim to address the problems associated with traditional passwords by introducing stronger, simpler, and more phishing-resistant user authentication methods. These standards mitigate Man-in-the-Middle attacks by using decentralized on-device authentication. Yet, their universal adoption remains a work in progress. Until then, a popular alternative for dealing with the password complexity is a Password manager such as [LessPass](https://www.lesspass.com/#/), [1Password](https://1password.com/), and [Bitwarden](https://bitwarden.com/), which offer enhanced security, convenience, and cross-platform access. However, these password managers are also prone to security and privacy risks especially and become a single point of failure when they store user passwords in the cloud. As password managers may also store other sensitive information such as credit card details and secured notes, the Cloud-based password managers with centralized storage become high value target hackers. Many cloud-based password managers implement additional security measures such as end-to-end encryption, zero-knowledge architecture, and multifactor authentication but once hackers get access to the encrypted password vaults, they become vulnerable to sophisticated encryption attacks. For example, In 2022, LastPass, serving 25 million users, experienced [significant security breaches](https://blog.lastpass.com/2023/03/security-incident-update-recommended-actions/). Attackers accessed a range of user data, including billing and email addresses, names, telephone numbers, and IP addresses. More alarmingly, the breach compromised customer vault data, revealing unencrypted website URLs alongside encrypted usernames, passwords, secure notes, and form-filled information. The access to the encrypted vaults allow [“offline attacks” for password cracking](https://krebsonsecurity.com/2023/09/lastpass-horse-gone-barn-bolted-is-strong-password/) attempts that may use powerful computers for trying millions of password guesses per second. In another incident, LastPass users were [locked out of their accounts due to MFA reset](https://www.bleepingcomputer.com/news/security/lastpass-users-furious-after-being-locked-out-due-to-mfa-resets/) after a security upgrade. In order to address these risks with cloud-based password managers, we are building a secured family-friendly password manager named “PlexPass” with an enhanced security and ease of use including multi-device support for family members but without relying on storing data in cloud.

## 1.0 Design Tenets and Features
----------------

The PlexPass is designed based on following tenets and features:

*   End-to-End Encryption: All data is encrypted using strong cryptographic algorithms. The decryption key will be derived from the user’s master password.
*   Zero-Knowledge Architecture: The password manager won’t have the ability to view the decrypted data unless explicitly instructed by the user.
*   No Cloud: It allows using the password manager to be used as a local command-line tool or as a web server for local hosting without storing any data in the cloud.
*   Great User Experience: It provides a great user-experience based on a command-line tool and a web-based responsive UI that can be accessed by local devices.
*   Strong Master Password: It encourages users to create a robust and strong master password.
*   Secure Password Generation: It allows users to generate strong, random passwords for users, reducing the temptation to reuse passwords.
*   Password Strength Analyzer: It evaluates the strength of stored passwords and prompt users to change weak or repeated ones.
*   Secure Import and Export: It allows users to import and export password vault data in a standardized, encrypted format so that users can backup and restore in case of application errors or device failures.
*   Data Integrity Checks: It verifies the integrity of the stored data to ensure it hasn’t been tampered with.
*   Version History: It stores encrypted previous versions of entries, allowing users to revert to older passwords or data if necessary.
*   Open-Source: The PlexPass is open-source so that the community can inspect the code, which can lead to the identification and rectification of vulnerabilities.
*   Regular Updates: It will be consistently updated to address known vulnerabilities and to stay aligned with best practices in cryptographic and security standards.
*   Physical Security: It ensures the physical security of the device where the password manager is installed, since the device itself becomes a potential point of vulnerability.
*   Data Breach Notifications: It allows uses to scan passwords with known breached password hashes (without compromising privacy) that may have been leaked in data breaches.
*   Multi-Device and Sharing: As a family-friendly password manager, PlexPass allows sharing passwords safely to the nearby trusted devices without the risks associated with online storage.
*   Clipboard Protection: It offers mechanisms like clearing the clipboard after a certain time to protect copied passwords.
*   Tagging and Organization: It provides users with the ability to organize entries using tags, categories, or folders for a seamless user experience.
*   Secure Notes: It stores encrypted notes and additional form-filled data.
*   Search and Filter Options: It provides intuitive search and filter capabilities.
*   Multi-Factor Authentication: PlexPass supports MFA based on [One-Time-Password](https://en.wikipedia.org/wiki/One-time_password) (OTP) and other standards.
*   Local Authentication: PlexPass will support standards such as [FIDO](https://fidoalliance.org/what-is-fido/) and [WebAuthN](https://webauthn.guide/) for local authentication based on biometrics and multi-factor authentication based on hardware keys such as [Yubikey](https://www.yubico.com/). 

## 2.0 Cryptography
----------------

### 2.1 Password Hashing

[OWasp](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), [IETF Best Practices](https://www.ietf.org/archive/id/draft-ietf-kitten-password-storage-04.html#section-4.2) and [Sc00bz](https://soatok.blog/2022/12/29/what-we-do-in-the-etc-shadow-cryptography-with-passwords/)(security researcher) recommends following for the password hashing:

*   Use [Argon2](https://en.wikipedia.org/wiki/Argon2) (winner of the 2015 [Password Hashing Competition](https://en.wikipedia.org/wiki/Password_Hashing_Competition)) with an iteration count of 2, and 1 degree of parallelism (if not available then use [scrypt](https://www.tarsnap.com/scrypt/scrypt.pdf) with cost parameter of (2^17), a minimum block size of 8, and a parallelization parameter of 1).
*   For FIPS-140 compliance, it recommends [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) with work factor of 600,000+ and with an internal hash function of HMAC-SHA-256. Other settings include:
    *   PBKDF2-HMAC-SHA1: 1,300,000 iterations
    *   PBKDF2-HMAC-SHA256: 600,000 iterations
    *   PBKDF2-HMAC-SHA512: 210,000 iterations
*   Consider using a [pepper](https://www.ietf.org/archive/id/draft-ietf-kitten-password-storage-04.html#section-4.2) to provide additional defense in depth.

Many of the popular password managers [fall short of these standards](https://dustri.org/b/the-quest-for-a-family-friendly-password-manager.html) but PlexPass will support [Argon2id](https://en.wikipedia.org/wiki/Argon2) with a memory cost of 64 MiB, iteration count of 3, and parallelism of 1; [PBKDF2-HMAC-SHA256](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2) with 650,000 iterations; and [salt](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#salting) with [pepper](https://www.ietf.org/archive/id/draft-ietf-kitten-password-storage-04.html#section-4.2) for enhanced security.

### 2.2 Encryption

PlexPass incorporates a robust encryption strategy that utilizes both symmetric and asymmetric encryption methodologies, in conjunction with envelope encryption, detailed as follows:

*   **Symmetric Encryption**: Based on [OWasp](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) recommendations, the private account information are safeguarded with Symmetric key algorithm of AES (Advanced Encryption Standard) with GCM (Galois/Counter Mode) mode that provides confidentiality and authenticity and uses key size of 256 bits (AES-256) for the highest security. The Symmetric key is used for both the encryption and decryption of accounts and sensitive data.
*   **Asymmetric Encryption**: PlexPass employs Elliptic Curve Cryptography (ECC) based Asymmetric key algorithm with SECP256k1 standard for encrypting Symmetric keys and sharing data with other users based on public key infrastructure (PKI). The public key is used for encrypting keys and shared data, while the private key is used for decryption. This allows users to share encrypted data without the need to exchange a secret key over the network.
*   **Envelope Encryption**: PlexPass’s envelope encryption mechanism involves encrypting a Symmetric data encryption key (DEK) with a Asymmetric encryption key (KEK). The Symmetric DEK is responsible for securing the actual user data, while the Asymmetric KEK is used to encrypt and protect the DEK itself. The top-level KEK key is then encrypted with a Symmetric key derived from the master user password and a pepper key for the local device. This multi-tiered encryption system ensures that even if data were to be accessed without authorization, it would remain undecipherable without the corresponding KEK.

## 3.0 Data Storage and Network Communication
------------------------------------------

With Envelope Encryption strategy, PlexPass ensures a multi-layered protective barrier for user accounts and sensitive information. This security measure involves encrypting data with a unique Symmetric key, which is then further secured using a combination of the user’s master password and a device-specific pepper key. The pepper key is securely stored within Hardware Security Modules (**HSMs**), providing an additional layer of defense. To generate the user’s secret key, PlexPass relies on the master password in tandem with the device’s pepper key, while ensuring that the master password itself is never stored locally or on any cloud-based platforms. PlexPass allows a versatile range of access points, including command-line tools, REST API, and a user-friendly interface. Although PlexPass is primarily designed for local hosting, it guarantees secure browser-to-local-server communications through the implementation of **TLS 1.3**, reflecting the commitment to the highest standards of network security.

### 3.1 Data Encryption

Following diagram illustrates how data is encrypted with envelop encryption scheme:

![](https://weblog.plexobject.com/images/envelop_enc.png)

Envelop Encryption

The above diagram illustrates that a master secret key is derived from the combination of the user’s master password and a device-specific pepper key. The device pepper key is securely stored within HSM storage solutions, such as the MacOS Keychain, or as encrypted files on other platforms. Crucially, neither the master user password nor the secret key are stored on any local or cloud storage systems.

This master secret key plays a pivotal role in the encryption process: it encrypts the user’s private asymmetric key, which then encrypts the symmetric user key. The symmetric user key is utilized for the encryption of user data and messages. Furthermore, the user’s private key is responsible for encrypting the private key of each Vault, which in turn is used to encrypt the Vault’s symmetric key and the private keys of individual Accounts.

Symmetric keys are employed for the encryption and decryption of data, while asymmetric keys are used for encrypting and decrypting other encryption keys, as well as for facilitating the secure sharing of data between multiple users. This layered approach to encryption ensures robust security and privacy of the user data within the system.

## 4.0 Domain Model
----------------

The following section delineates the domain model crafted for implementing a password manager:

### 4.1 User

A user refers to any individual utilizing the password manager, which may include family members or other users. The accounts information corresponding to each user is secured with a unique key, generated by combining the user’s master password with a device-specific pepper key.

### 4.2 Vault

A user has the capability to create multiple vaults, each serving as a secure storage space for account information and sensitive data, tailored for different needs. Additionally, users can grant access to their vaults to family members or friends, enabling them to view or modify shared credentials for Wi-Fi, streaming services, and other applications.

### 4.3 Account and Secure Notes

The Account entity serves as a repository for a variety of user data, which may include credentials for website access, credit card details, personal notes, or other bespoke attributes. Key attributes of the Account entity include:

*   label and description of account
*   username
*   password
*   email
*   website
*   category
*   tags
*   OTP and other MFA credentials
*   custom fields for credit cards, address and other data
*   secure notes for storing private notes

### 4.4 Password Policy

The Password Policy stipulates the guidelines for creating or adhering to specified password requirements, including:

*   Option for a random or memorable password.
*   A minimum quota of uppercase letters to include.
*   A requisite number of lowercase letters to include.
*   An essential count of digits to incorporate.
*   A specified number of symbols to be included.
*   The minimum allowable password length.
*   The maximum allowable password length.
*   An exclusion setting to omit ambiguous characters for clarity.

### 4.5 Messages

The Message structure delineates different categories of messages employed for managing background operations, distributing information, or alerting users about potential password breaches.

### 4.6 Hashing and Cryptography algorithms

PlexPass offers the option to select from a variety of robust hashing algorithms, including Pbkdf2HmacSha256 and ARGON2id, as well as cryptographic algorithms like Aes256Gcm and ChaCha20Poly1305.

### 4.7 PasswordAnalysis

PasswordAnalysis encapsulates the outcome of assessing a password, detailing aspects such as:

*   The strength of the password.
*   Whether the password has been compromised or flagged in “Have I Been Pwned” (HIBP) breaches.
*   Similarity to other existing passwords.
*   Similarity to previously used passwords.
*   Reuse of the password across multiple accounts.
*   The entropy level, indicating the password’s complexity.
*   Compliance with established password creation policies

### 4.8 VaultAnalysis

VaultAnalysis presents a comprehensive evaluation of the security posture of all credentials within a vault, highlighting the following metrics:

*   The total number of accounts stored within the vault.
*   The quantity of passwords classified as strong due to their complexity and resistance to cracking attempts.
*   The tally of passwords deemed to have moderate strength, providing reasonable but not optimal security.
*   The count of passwords considered weak and vulnerable to being easily compromised.
*   The number of passwords that are not only strong but also have not been exposed in breaches or found to be reused.
*   The amount of credentials that have been potentially compromised or found in known data breaches.
*   The number of passwords that are reused across different accounts within the vault.
*   The tally of passwords that are notably similar to other passwords in the vault, posing a risk of cross-account vulnerability.
*   The count of current passwords that share similarities with the user’s past passwords, which could be a security concern if old passwords have been exposed.

### 4.9 System Configuration

The system configuration outlines a range of settings that determine the data storage path, HTTP server parameters, public and private key specifications for TLS encryption, preferred hashing and cryptographic algorithms, and other essential configurations.

### 4.10 UserContext

PlexPass mandates that any operation to access or modify user-specific information, including accounts, vaults, and other confidential data, is strictly governed by user authentication. The ‘UserContext’ serves as a secure container for the user’s authentication credentials, which are pivotal in the encryption and decryption processes of hierarchical cryptographic keys, adhering to the principles of envelope encryption.

## 5.0 Database Model and Schema
-----------------------------

In general, there is a direct correlation between the domain model and the database schema, with the latter focusing primarily on key identifying attributes while preserving the integrity of user, vault, and account details through encryption. Furthermore, the database schema is designed to manage the cryptographic keys essential for the secure encryption and decryption of the stored data. The following section details the principal entities of the database model:

### 5.1 UserEntity

The UserEntity captures essential user attributes including the user_id and username. It securely retains encrypted user data alongside associated salt and nonce—components utilized in the encryption and decryption process. This entity leverages a secret-key, which is generated through a combination of the user’s master password and a unique device-specific pepper key. Importantly, the secret-key itself is not stored in the database to prevent unauthorized access.

### 5.2 LoginSessionEntity

The LoginSessionEntity records the details of user sessions, functioning as a mechanism to verify user access during remote engagements through the API or web interfaces.

### 5.3 CryptoKeyEntity

The CryptoKeyEntity encompasses both asymmetric and symmetric encryption keys. The symmetric key is encrypted by the asymmetric private key, which itself is encrypted using the public key of the parent CryptoKeyEntity. Key attributes include:

*   The unique identifier of the key.
*   The identifier of the parent key, which, if absent, signifies it as a root key—this is enforced as non-null for database integrity.
*   The user who owns the crypto key.
*   The keyable_id linked through a polymorphic association.
*   The keyable_type, determining the nature of the association.
*   The salt utilized in the encryption process.
*   The nonce that ensures encryption uniqueness.
*   The public key utilized for encryption purposes.
*   The secured private key, which is encrypted and used for value encryption tasks.

### 5.4 VaultEntity

The VaultEntity is the structural representation of a secure repository designed for the safekeeping of account credentials and sensitive information. The primary attributes of the VaultEntity are as follows:

*   The user ID of the vault’s owner, indicating possession and control.
*   The designated name given to the vault for identification.
*   The category or type of vault, specifying its purpose or nature.
*   The salt applied during the encryption process, enhancing security.
*   The nonce, a number used once to prevent replay attacks, ensuring the uniqueness of each encryption.
*   The vault’s contents, securely encrypted to protect the confidentiality of the information it holds.
*   Other metadata such as unique identifier, version and timestamp for tracking changes.

### 5.5 AccountEntity

The AccountEntity serves as the database abstraction for the Account object, which is responsible for storing various user data, including account credentials, secure notes, and other bespoke attributes. Its principal characteristics are:

*   The vault_id that links the account to its respective vault.
*   The archived_version, which holds historical data of the account for reference or restoration purposes.
*   The salt, a random data input that is used in conjunction with hashing to ensure the uniqueness of each hash and prevent attacks such as hash collisions.
*   The key-nonce, a one-time use number utilized in the encryption process to guarantee the security of each encryption operation.
*   The encrypted_value, which is the securely encrypted form of the account’s data, preserving the confidentiality and integrity of user information.
*   The hash of primary attributes, which functions as a unique fingerprint to identify and prevent duplicate accounts from being created inadvertently.
*   Other metadata such as unique identifier, version and timestamp for tracking changes.

### 5.6 ArchivedAccountEntity

The ArchivedAccountEntity functions as a historical repository for AccountEntity records. Whenever a password or another vital piece of information within an account is altered, the original state of the account is preserved in this entity. This allows users to conveniently review previous versions of their account data, providing a clear audit trail of changes over time.

### 5.7 UserVaultEntity

The UserVaultEntity acts as the relational bridge between individual User entities and VaultEntity records. It facilitates the shared access of a single VaultEntity among multiple users while enforcing specific access control measures and adherence to predefined policies. This entity enables collaborative management of vault data based on access control policies and user’s permissions.

### 5.8 MessageEntity

The MessageEntity is a storage construct for various types of messages. These messages facilitate user notifications and alerts, sharing of vaults and account details, and scheduling of background processes. The entity ensures that operations meant to be executed on behalf of the user, such as sending notifications or processing queued tasks, are handled efficiently and securely.

### 5.9 AuditEntity

The AuditEntity functions as a comprehensive record for monitoring user activities within the system, primarily for enhancing security oversight. Key attributes of this entity are as follows:

*   The user associated with the audit event.
*   The specific category of the audit event.
*   The originating ip-adderss from which the event was triggered.
*   A set of context parameters providing additional detail about the event.
*   The message which encapsulates the essence of the audit event.
*   Additional `metadata` that provides further insight into the audit occurrence.

### 5.10 ACLEntity

The ACLEntity is a structural component that dictates permissions within the system, controlling user access to resources such as Vaults. The principal attributes of this entity are outlined as follows:

*   The user-id to which the ACL pertains, determining who the permissions are assigned to.
*   The resource-type indicating the category of resource the ACL governs.
*   The resource-id which specifies the particular instance of the resource under ACL.
*   A permission mask that encodes the rights of access, such as read or write privileges.
*   The scope parameters that may define the context or extent of the permissions.
*   Supplementary metadata which could include the ACL’s identifier, version number, and the timestamp of its creation or last update.

## 6.0 Data Repositories
---------------------

Data repositories act as the intermediary layer between the underlying database and the application logic. These repositories are tasked with providing specialized data access operations for their respective database models, such as the UserRepository, ACLRepository, LoginSessionRepository, and so forth. They offer a suite of standardized methods for data manipulation—adding, updating, retrieving, and searching entries within the database.

Each repository typically adheres to a common Repository interface, ensuring consistency and predictability across different data models. Additionally, they may include bespoke methods that cater to specific requirements of the data they handle. Leveraging Rust’s Diesel library, these repositories enable seamless interactions with relational databases like SQLite, facilitating the efficient execution of complex queries and ensuring the integrity and performance of data operations within the system.

### 6.1 Encryption Implementation with Repositories

## 7.0 Domain Services
-------------------

The heart of the password manager’s functionality is orchestrated by domain services, each tailored to execute a segment of the application’s core business logic by interacting with data repository interfaces. These services encompass a diverse range of operations integral to the password manager such as:

### 7.1 **UserService**

UserService is entrusted with user management tasks, including registration, updates, and deletion of user profiles. It defines following operations:

```rust
[async_trait]
pub trait UserService {
    // signup and create a user.
    async fn signup_user(&self,
                         user: &User,
                         master_password: &str,
                         context: HashMap<String, String>, ) -> PassResult<(UserContext, UserToken)>;

    // signin and retrieve the user.
    async fn signin_user(
        &self,
        username: &str,
        master_password: &str,
        context: HashMap<String, String>,
    ) -> PassResult<(UserContext, User, UserToken)>;

    // logout user
    async fn signout_user(&self, ctx: &UserContext, login_session_id: &str) -> PassResult<()>;

    // get user by id.
    async fn get_user(&self, ctx: &UserContext, id: &str) -> PassResult<(UserContext, User)>;

    // updates existing user.
    async fn update_user(&self, ctx: &UserContext, user: &User) -> PassResult<usize>;

    // delete the user by id.
    async fn delete_user(&self, ctx: &UserContext, id: &str) -> PassResult<usize>;
}
```

### 7.2 **VaultService**

VaultService facilitates the creation, modification, and deletion of vaults, in addition to managing access controls. It defines following operations:

 ```rust
[async_trait]
pub trait VaultService {
    // create an vault.
    async fn create_vault(&self, ctx: &UserContext, vault: &Vault) -> PassResult<usize>;

    // updates existing vault.
    async fn update_vault(&self, ctx: &UserContext, vault: &Vault) -> PassResult<usize>;

    // get the vault by id.
    async fn get_vault(&self, ctx: &UserContext, id: &str) -> PassResult<Vault>;

    // delete the vault by id.
    async fn delete_vault(&self, ctx: &UserContext, id: &str) -> PassResult<usize>;

    // find all vaults by user_id without account summaries.
    async fn get_user_vaults(&self, ctx: &UserContext) -> PassResult<Vec<Vault>>;

    // account summaries.
    async fn account_summaries_by_vault(
        &self,
        ctx: &UserContext,
        vault_id: &str,
        q: Option<String>,
    ) -> PassResult<Vec<AccountSummary>>;
}
```

### 7.3 **AccountService**

AccountService oversees the handling of account credentials, ensuring secure storage, retrieval, and management. It defines following operations:

 ```rust
[async_trait]
pub trait AccountService {
    // create an account.
    async fn create_account(&self, ctx: &UserContext, account: &Account) -> PassResult<usize>;

    // updates existing account.
    async fn update_account(&self, ctx: &UserContext, account: &Account) -> PassResult<usize>;

    // get account by id.
    async fn get_account(&self, ctx: &UserContext, id: &str) -> PassResult<Account>;

    // delete the account by id.
    async fn delete_account(&self, ctx: &UserContext, id: &str) -> PassResult<usize>;

    // find all accounts by vault.
    async fn find_accounts_by_vault(
        &self,
        ctx: &UserContext,
        vault_id: &str,
        predicates: HashMap<String, String>,
        offset: i64,
        limit: usize,
    ) -> PassResult<PaginatedResult<Account>>;

    // count all accounts by vault.
    async fn count_accounts_by_vault(
        &self,
        ctx: &UserContext,
        vault_id: &str,
        predicates: HashMap<String, String>,
    ) -> PassResult<i64>;
}
```

### 7.4 **EncryptionService**

EncryptionService provides the encryption and decryption operations for protecting sensitive data. It defines following operations:

```rust
[async_trait]
pub trait EncryptionService {
    // generate private public keys
    fn generate_private_public_keys(&self,
                                    secret: Option<String>,
    ) -> PassResult<(String, String)>;

    // encrypt asymmetric
    fn asymmetric_encrypt(&self,
                          pk: &str,
                          data: Vec<u8>,
                          encoding: EncodingScheme,
    ) -> PassResult<Vec<u8>>;

    // decrypt asymmetric
    fn asymmetric_decrypt(&self,
                          sk: &str,
                          data: Vec<u8>,
                          encoding: EncodingScheme,
    ) -> PassResult<Vec<u8>>;


    // encrypt symmetric
    fn symmetric_encrypt(&self,
                         salt: &str,
                         pepper: &str,
                         secret: &str,
                         data: Vec<u8>,
                         encoding: EncodingScheme,
    ) -> PassResult<Vec<u8>>;

    // decrypt symmetric
    fn symmetric_decrypt(&self,
                         pepper: &str,
                         secret: &str,
                         data: Vec<u8>,
                         encoding: EncodingScheme,
    ) -> PassResult<Vec<u8>>;
}
```

### 7.5 **ImportExportService**

ImportExportService allows users to import account data into vaults or export it for backup or other purposes, ensuring data portability. It defines following operations:

```rust
[async_trait]
pub trait ImportExportService {
    // import accounts.
    async fn import_accounts(&self,
                             ctx: &UserContext,
                             vault_id: Option<String>,
                             vault_kind: Option<VaultKind>,
                             password: Option<String>,
                             encoding: EncodingScheme,
                             data: &[u8],
                             callback: Box<dyn Fn(ProgressStatus) + Send + Sync>,
    ) -> PassResult<ImportResult>;

    // export accounts.
    async fn export_accounts(&self,
                             ctx: &UserContext,
                             vault_id: &str,
                             password: Option<String>,
                             encoding: EncodingScheme,
                             callback: Box<dyn Fn(ProgressStatus) + Send + Sync>,
    ) -> PassResult<(String, Vec<u8>)>;
}
```

Note: The import and export operations may take a long time so it supports a callback function to update user with progress of the operation.

### 7.6 **MessageService**

MessageSevice manages the creation, delivery, and processing of messages within the system, whether for notifications or data sharing. It defines following operations:

 ```rust
[async_trait]
pub trait MessageService {
    // create an message.
    async fn create_message(&self, ctx: &UserContext, message: &Message) -> PassResult<usize>;

    // updates existing message flags
    async fn update_message(&self, ctx: &UserContext, message: &Message) -> PassResult<usize>;

    // delete the message by id.
    async fn delete_message(&self, ctx: &UserContext, id: &str) -> PassResult<usize>;

    // find all messages by vault.
    async fn find_messages_by_user(
        &self,
        ctx: &UserContext,
        kind: Option<MessageKind>,
        offset: i64,
        limit: usize,
    ) -> PassResult<PaginatedResult<Message>>;
}
```

### 7.7 **PasswordService**

PasswordService offers operations for the generation of secure passwords, alongside analytical features to assess password strength and security. It defines following operations:

 ```rust
[async_trait]
pub trait PasswordService {
    // create strong password.
    async fn generate_password(&self, policy: &PasswordPolicy) -> Option<String>;

    // check strength of password.
    async fn password_info(&self, password: &str) -> PassResult<PasswordInfo>;

    // check strength of password.
    async fn password_compromised(&self, password: &str) -> PassResult<bool>;

    // check if email is compromised.
    async fn email_compromised(&self, email: &str) -> PassResult<String>;

    // check similarity of password.
    async fn password_similarity(&self, password1: &str, password2: &str) -> PassResult<PasswordSimilarity>;

    // analyze passwords and accounts of all accounts in given vault
    // It returns hashmap by account-id and password analysis
    async fn analyze_all_account_passwords(&self, ctx: &UserContext, vault_id: &str) -> PassResult<VaultAnalysis>;

    // analyze passwords and accounts of all accounts in all vaults
    // It returns hashmap by (vault-id, account-id) and password analysis
    async fn analyze_all_vault_passwords(&self, ctx: &UserContext) -> PassResult<HashMap<String, VaultAnalysis>>;

    // schedule password analysis for vault
    async fn schedule_analyze_all_account_passwords(&self, ctx: &UserContext, vault_id: &str) -> PassResult<()>;

    // schedule password analysis for all vaults
    async fn schedule_analyze_all_vault_passwords(&self, ctx: &UserContext) -> PassResult<()>;
}
```

### 7.8 **ShareVaultAccountService**

ShareVaultAccountService handles the intricacies of sharing vaults and accounts, enabling collaborative access among authorized users. It defines following operations:

 ```rust
[async_trait]

/// Service interface for sharing vaults or accounts.
pub trait ShareVaultAccountService {
    // share vault with another user
    async fn share_vault(
        &self,
        ctx: &UserContext,
        vault_id: &str,
        target_username: &str,
        read_only: bool,
    ) -> PassResult<usize>;

    // share account with another user
    async fn share_account(
        &self,
        ctx: &UserContext,
        account_id: &str,
        target_username: &str,
    ) -> PassResult<usize>;

    // lookup usernames
    async fn lookup_usernames(
        &self,
        ctx: &UserContext,
        q: &str,
    ) -> PassResult<Vec<String>>;

    // handle shared vaults and accounts from inbox of messages
    async fn handle_shared_vaults_accounts(
        &self,
        ctx: &UserContext,
    ) -> PassResult<(usize, usize)>;
}
```

PlexPass employs a Public Key Infrastructure (PKI) for secure data sharing, whereby a user’s vault and account keys are encrypted using the intended recipient’s public key. This encrypted data is then conveyed as a message, which is deposited into the recipient’s inbox. Upon the recipient’s next login, they use their private key to decrypt the message. This process of decryption serves to forge a trust link, granting the recipient authorized access to the shared vault and account information, strictly governed by established access control protocols.

### 7.9 **AuditLogService**

AuditLogService specializes in the retrieval and querying of audit logs, which are automatically generated to track activities for security monitoring. It defines following operations:

 ```rust
[async_trait]
pub trait AuditLogService {
    async fn find(&self,
            ctx: &UserContext,
            predicates: HashMap<String, String>,
            offset: i64,
            limit: usize,
    ) -> PassResult<PaginatedResult<AuditLog>>;
}
```

## 8.0 API and UI Controllers
--------------------------

PlexPass employs API controllers to establish RESTful endpoints and UI controllers to manage the rendering of the web interface. Typically, there’s a direct correlation between each API and UI controller and their respective domain services. These controllers act as an intermediary, leveraging the domain services to execute the core business logic.

## 9.0 Commands
------------

PlexPass adopts the command pattern for its command line interface, where each command is associated with a specific user action within the password management system.

## 10.0 Design Decisions
---------------------

The architectural considerations for the design and implementation of PlexPass – a password manager – encompassed several key strategies:

1.  Security-First Approach: PlexPass design ensured the highest level of security for stored credentials was paramount. This involved integrating robust encryption methods, such as AES-256 for data at rest and TLS 1.3 for data in transit, alongside employing secure hashing algorithms for password storage.
2.  User-Centric Design: User experience was prioritized by providing a clean, intuitive interface and seamless interactions, whether through a command-line interface, RESTful APIs, or a web application.
3.  Performance: PlexPass chose Rust for implementation to leverage its performance, safety, and robustness, ensuring a highly secure and efficient password manager.
4.  Modular Structure: PlexPass was designed with modular architecture by segmenting the application into distinct services, controllers, and repositories to facilitate maintenance and future enhancements.
5.  Object/Relation Mapping: PlexPass utilizes the Diesel framework for its database operations, which offers an extensive ORM toolkit for efficient data handling and compatibility with various leading relational databases.
6.  MVC Architecture: PlexPass employs the Model-View-Controller (MVC) architectural pattern to structure its web application, enhancing the clarity and maintainability of the codebase. In this architecture, the Model component represents the data and the business logic of the application. It’s responsible for retrieving, processing, and storing data, and it interacts with the database layer. The model defines the essential structures and functions that represent the application’s core functionality and state. The View utilizes the Askama templating engine, a type-safe and fast Rust templating engine, to dynamically generate HTML content. The Controller acts as an intermediary between the Model and the View.
7.  Extensibility and Flexibility: PlexPass design considered future extensions to allow for additional features such as shared vaults and multi-factor authentication to be added without major overhauls.
8.  Internationalization and Localization: PlexPass employs the Fluent library, a modern localization system designed for natural-sounding translations. This ensures that PlexPass user-interface is linguistically and culturally accessible to users worldwide.
9.  Cross-Platform Compatibility: PlexPass design ensured compatibility across different operating systems and devices, enabling users to access their password vaults from any platform.
10. Authorization and Access Control: PlexPass rigorously upholds stringent ownership and access control measures, guaranteeing that encrypted private data remains inaccessible without appropriate authentication. Furthermore, it ensures that other users can access shared Vaults and Accounts solely when they have been explicitly authorized with the necessary read or write permissions.
11.  Privacy by Design: User privacy was safeguarded by adopting principles like minimal data retention and ensuring that sensitive information, such as master passwords, is never stored in a file or persistent database.
12.  Asynchronous Processing: PlexPass uses asynchronous processing for any computational intenstive tasks such as password analysis so that UI and APIs are highly responsive.
13.  Data Portability: PlexPass empowers users with full control over their data by offering comprehensive import and export features, facilitating effortless backup and data management.
14.  Robust Error Handling and Logging: PlexPass applies comprehensive logging, auditing and error-handling mechanisms to facilitate troubleshooting and enhance the security audit trail.
15.  Compliance with Best Practices: PlexPass design adhered to industry best practices and standards for password management and data protection regulations throughout the development process.
16.  Health Metrics: PlexPass incorporates Prometheus, a powerful open-source monitoring and alerting toolkit, to publish and manage its API and business service metrics. This integration plays a crucial role in maintaining the reliability and efficiency of the system through enhanced monitoring capabilities.

## 11.0 User Guide
---------------

The following section serves as a practical guide for utilizing PlexPass, a secured password management solution. Users have the convenience of interacting with PlexPass through a variety of interfaces including a command-line interface (CLI), RESTful APIs, and a user-friendly web application.

### 11.1 Build and Installation

Checkout PlexPass from https://github.com/bhatti/PlexPass and then build using:
```
git clone git@github.com:bhatti/PlexPass.git
cd PlexPass
cargo build --release && ./target/release/plexpass server
```

Alternatively, you can use Docker for the server by pulling plexpass image as follows:
```

docker pull plexobject/plexpass:latest
docker run -p 8080:8080 -p 8443:8443 -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY 
	-e DATA_DIR=/data -e CERT_FILE=/data/cert-pass.pem 
    -e KEY_FILE=/data/key-pass.pem -v $PARENT_DIR/PlexPassData:/data plexpass server
```

Note: You only need to run server when using REST APIs or a UI for the web application.

### 11.2 User Registration

Before engaging with the system, users are required to complete the registration process. They have the following options to establish their access:

#### 11.2.1 Command Line
```

./target/release/plexpass -j true --master-username charlie --master-password *** create-user
```

The -j argument generates a JSON output such as:
```json
{
  "user_id": "3b12c573-d4e4-4470-a1b4-ac7689c40e8a",
  "version": 0,
  "username": "charlie",
  "name": null,
  "email": null,
  "locale": null,
  "light_mode": null,
  "icon": null,
  "attributes": [],
  "created_at": "2023-11-06T04:25:28.004321",
  "updated_at": "2023-11-06T04:25:28.004325"
}
```

#### 11.2.2 Docker CLI
```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data 
	-v $PARENT_DIR/PlexPassData:/data plexpass -j true 
    --master-username charlie --master-password *** create-user
```

#### 11.2.3 REST API
```bash
curl -v -k https://localhost:8443/api/v1/auth/signup 
	--header "Content-Type: application/json; charset=UTF-8" 
    -d '{"username": "david", "master_password": "***"}'
```

or
```bash
headers = {'Content-Type': 'application/json'}
data = {'username': 'charlie', 'master_password': '***'}
resp = requests.post(SERVER + '/api/v1/auth/signin', json = data,
                     headers = headers, verify = False)
```

#### 11.2.4 Web Application UI

Once, the server is started, you can point a browser to the server, e.g., https://localhost:8443 and it will show you interface for signin and registration:

![](https://weblog.plexobject.com/images/signup.png)

### 11.3 User Signin

The user-signin is requied when using REST APIs but CLIBefore engaging with the system, users are required to complete the registration process. The REST API will generate a JWT Token, which will be required for accessing all other APIs, e.g.,

#### 11.3.1 REST APIs
```bash
curl -v -k https://localhost:8443/api/v1/auth/signin 
	--header "Content-Type: application/json; charset=UTF-8" 
    -d '{"username": "bob", "master_password": ""}'
```
It will show the JWT Token in the response, e.g.,
```bash
< HTTP/2 200
< content-length: 50
< content-type: application/json
< access_token: eyJ0eXA***
< vary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers
< date: Tue, 07 Nov 2023 20:19:42 GMT
<
```
#### 11.3.2 WebApp UI

Alternatively, you can signin to the web application if you have already registered, e.g.,

![](https://weblog.plexobject.com/images/signin.png)

Note: Once, you are signed in, you will see all your vaults and accounts as follows but we will skip the Web UI from rest of the user-guide section:

![](https://weblog.plexobject.com/images/home_ui.png)

Home UI

Note: PlexPass Web application automatically flags weak or compromised passwords with red background color.

#### 11.4.1 Command Line Help

You can use -h argument to see full list of commands with PlexPass CLI, e.g.,
```bash
PlexPass - a locally hostable secured password manager

Usage: plexpass [OPTIONS] <COMMAND>

Commands:
  server

  get-user

  create-user

  update-user

  delete-user

  create-vault

  update-vault

  delete-vault

  get-vault

  get-vaults

  create-account

  update-account

  get-account

  get-accounts

  delete-account

  query-audit-logs

  create-category

  delete-category

  get-categories

  generate-private-public-keys

  asymmetric-encrypt

  asymmetric-decrypt

  symmetric-encrypt

  symmetric-decrypt

  import-accounts

  export-accounts

  generate-password

  password-compromised

  password-strength

  email-compromised

  analyze-vault-passwords

  analyze-all-vaults-passwords

  search-usernames

  share-vault

  share-account

  help
          Print this message or the help of the given subcommand(s)

Options:
  -j, --json-output <JSON_OUTPUT>
          json output of result from action [default: false] [possible values: true, false]
  -d, --data-dir <DATA_DIR>
          Sets a data directory
      --device-pepper-key <DEVICE_PEPPER_KEY>
          Device pepper key
      --crypto-algorithm <CRYPTO_ALG>
          Sets default crypto algorithm [possible values: aes256-gcm, cha-cha20-poly1305]
      --hash-algorithm <HASH_ALG>
          Sets default crypto hash algorithm [possible values: pbkdf2-hmac-sha256, argon2id]
      --master-username <MASTER_USERNAME>
          The username of local user
      --master-password <MASTER_PASSWORD>
          The master-password of user
  -c, --config <FILE>
          Sets a custom config file
  -h, --help
          Print help information
  -V, --version
          Print version information
```

### 11.4 User Profile

#### 11.4.1 Command Line

You can view your user profile using:
```bash
./target/release/plexpass -j true --master-username charlie 
	--master-password *** get-user
```

Which will show your user profile such as:
```json
{
  "user_id": "d163a4bb-6767-4f4c-845f-86874a04fe20",
  "version": 0,
  "username": "charlie",
  "name": null,
  "email": null,
  "locale": null,
  "light_mode": null,
  "icon": null,
  "attributes": [],
  "created_at": "2023-11-07T20:30:32.063323960",
  "updated_at": "2023-11-07T20:30:32.063324497"
}
```

#### 11.4.2 REST API

You can view your user profile using:
```bash
curl -k https://localhost:8443/api/v1/users/me 
	--header "Content-Type: application/json; charset=UTF-8"  
    --header "Authorization: Bearer $AUTH_TOKEN"
```
#### 11.4.3 Docker CLI

You can view your user profile with docker CLI as follows:
```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY 
	-e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass -j true 
    --master-username charlie --master-password *** get-user
```
### 11.5 Update User Profile

#### 11.5.1 Command Line

You can update your user profile using CLI as follows:
```bash
./target/release/plexpass -j true --master-username charlie 
	--master-password *** update-user --name "Charles" --email "charlie@mail.com"
```
#### 11.5.2 REST API

You can update your user profile using REST APIs as follows:
```bash
./target/release/plexpass -j true --master-username charlie 
	--master-password *** --name "Charles" --email "charlie@mail.com"
```
#### 11.5.2 Docker CLI

You can update your user profile using docker CLI as follows:
```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY 
	-e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data 
    -j true --master-username charlie 
	--master-password *** update-user --name "Charles" --email "charlie@mail.com"
```

### 11.6 Creating Vaults

PlexPass automatically creates a few Vaults upon registration but you can create additional vaults as follows:

#### 11.6.1 Command Line

You can create new Vault using CLI as follows:
```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password *** create-vault --title MyVault --kind Logins
```

#### 11.6.2 REST API

You can create new Vault using REST API as follows:
```bash
curl -v -k -X POST https://localhost:8443/api/v1/vaults 
	--header "Content-Type: application/json; charset=UTF-8" 
    --header "Authorization: Bearer $AUTH_TOKEN" 
    -d '{"title": "NewVault"}'
```

#### 11.6.3 Docker CLI

You can create new Vault using Docker CLI as follows:
```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY 
	-e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass 
    -j true --master-username frank --master-password ** 
    create-vault --title MyVault
```

### 11.7 Quering Vaults

#### 11.7.1 Command Line

You can query all Vaults using CLI as follows:
```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password ** get-vaults
```
Which will show list of vaults such as:
```json
[
  {
    "vault_id": "44c0f4bc-8aca-46ac-a80a-9bd25c8f06aa",
    "version": 0,
    "owner_user_id": "c81446b7-8de4-41d7-b5a7-36d4075777bc",
    "title": "Identity",
    "kind": "Logins",
    "created_at": "2023-11-08T03:45:44.163762",
    "updated_at": "2023-11-08T03:45:44.163762"
  },
  {
    "vault_id": "070ba646-192b-47df-8134-c6ed40056575",
    "version": 0,
    "owner_user_id": "c81446b7-8de4-41d7-b5a7-36d4075777bc",
    "title": "Personal",
    "kind": "Logins",
    "created_at": "2023-11-08T03:45:44.165378",
    "updated_at": "2023-11-08T03:45:44.165378"
  },
  ..
]
```

#### 11.7.2 REST API

You can query Vaults using REST API as follows:
```bash
curl -v -k https://localhost:8443/api/v1/vaults 
	--header "Content-Type: application/json; charset=UTF-8" 
    --header "Authorization: Bearer $AUTH_TOKEN"
```

#### 11.7.3 Docker CLI

You can create new Vault using Docker CLI as follows:
```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY 
	-e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data 
    plexpass -j true --master-username frank 
    --master-password ** get-vaults
```

### 11.8 Show Specific Vault Data

#### 11.8.1 Command Line

You can query specific Vault using CLI as follows:
```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password ** --vault-id 44c0f4bc-8aca-46ac-a80a-9bd25c8f06aa
```

Which will show list of vaults such as:
```json
{
  "vault_id": "44c0f4bc-8aca-46ac-a80a-9bd25c8f06aa",
  "version": 0,
  "owner_user_id": "c81446b7-8de4-41d7-b5a7-36d4075777bc",
  "title": "Identity",
  "kind": "Logins",
  "icon": null,
  "entries": null,
  "analysis": null,
  "analyzed_at": null,
  "created_at": "2023-11-08T03:45:44.163762",
  "updated_at": "2023-11-08T03:45:44.163762"
}
```

#### 11.8.2 REST API

You can show a specific Vault using REST API as follows where ’44c0f4bc-8aca-46ac-a80a-9bd25c8f06aa’ is the vault-id:
```bash
curl -v -k https://localhost:8443/api/v1/vaults/44c0f4bc-8aca-46ac-a80a-9bd25c8f06aa 
	--header "Content-Type: application/json; charset=UTF-8" 
    --header "Authorization: Bearer $AUTH_TOKEN"
```

#### 11.8.3 Docker CLI

You can create new Vault using Docker CLI as follows:
```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY 
	-e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass 
    -j true --master-username frank --master-password * 
    get-vault --vault-id 44c0f4bc-8aca-46ac-a80a-9bd25c8f06aa
```

### 11.9 Updating a Vault Data

#### 11.9.1 Command Line

You can update a Vault using CLI as follows:
```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password *** update-vault --vault-id 44c0f4bc-8aca-46ac-a80a-9bd25c8f06aa 
    --icon newicon --title new-title
```

#### 11.9.2 REST API

You can update a Vault using REST API as follows:
```bash
curl -v -k -X PUT https://localhost:8443/api/v1/vaults/44c0f4bc-8aca-46ac-a80a-9bd25c8f06aa 
	--header "Content-Type: application/json; charset=UTF-8" 
    --header "Authorization: Bearer $AUTH_TOKEN"  
    -d '{"vault_id": "44c0f4bc-8aca-46ac-a80a-9bd25c8f06aa", "version": 0, "title": "new-title"}'
```

#### 11.9.3 Docker CLI

You can update a Vault using Docker CLI as follows:
```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY 
	-e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass 
    -j true --master-username frank --master-password *** 
    update-vault --vault-id $44c0f4bc-8aca-46ac-a80a-9bd25c8f06aa --title new-title
```

### 11.10 Deleting a Vault Data

#### 11.10.1 Command Line

You can delete a Vault using CLI as follows:
```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password *** delete-vault --vault-id 44c0f4bc-8aca-46ac-a80a-9bd25c8f06aa
```

#### 11.10.2 REST API

You can delete a Vault using REST API as follows:

```bash
curl -v -k -X DELETE https://localhost:8443/api/v1/vaults/44c0f4bc-8aca-46ac-a80a-9bd25c8f06aa 
	--header "Content-Type: application/json; charset=UTF-8" 
    --header "Authorization: Bearer $AUTH_TOKEN"
```

#### 11.10.3 Docker CLI

You can update a Vault using Docker CLI as follows:

```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY 
	-e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass 
    -j true --master-username frank --master-password *** 
    delete-vault --vault-id 44c0f4bc-8aca-46ac-a80a-9bd25c8f06aa
```

### 11.11 Creating an Account Data

#### 11.11.1 Command Line

You can create an Account using CLI as follows:

```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password *** --vault-id 44c0f4bc-8aca-46ac-a80a-9bd25c8f06aa 
    --label "My Bank Login" --username samuel --email "myemail@somewhere.com" 
    --url "https://mybank.com"  --category "Banking" 
    --password "***" --notes "Lorem ipsum dolor sit amet"
```

#### 11.11.2 REST API

You can create an Account using REST API as follows:
```bash
curl -v -k -X POST https://localhost:8443/api/v1/vaults 
	--header "Content-Type: application/json; charset=UTF-8" 
    --header "Authorization: Bearer $AUTH_TOKEN" 
    -d '{"vault_id": "44c0f4bc-8aca-46ac-a80a-9bd25c8f06aa", "label": "Amazon", "username": "harry", "password": "**", "website_url": "https://www.amazon.com", "email": "harry@bitvault.com"}'
```

#### 11.11.3 Docker CLI

You can create an Account using Docker CLI as follows:
```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY 
	-e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass 
	-j true --master-username eddie 
	--master-password *** --vault-id 44c0f4bc-8aca-46ac-a80a-9bd25c8f06aa 
    --label "My Bank Login" --username samuel --email "myemail@somewhere.com" 
    --url "https://mybank.com"  --category "Banking" 
    --password "***" --notes "Lorem ipsum dolor sit amet"
```

### 11.12 Querying Data

#### 11.12.1 Command Line

You can query Accounts data using CLI as follows:
```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password *** get-accounts 
    --vault-id 44c0f4bc-8aca-46ac-a80a-9bd25c8f06aa --q "amazon"
```
You can search your accounts based on username, email, categories, tags, label and description with above command. For example, above command will show all amazon accounts.

#### 11.12.2 REST API

You can query Accounts using REST API as follows:
```bash
curl -v -k --header "Content-Type: application/json; charset=UTF-8" 
	--header "Authorization: Bearer $AUTH_TOKEN" 
    "https://localhost:8443/api/v1/vaults/44c0f4bc-8aca-46ac-a80a-9bd25c8f06aa/accounts?q=amazon" 
```

#### 11.12.3 Docker CLI

You can create an Account using Docker CLI as follows:
```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY 
	-e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass 
	-j true --master-username eddie 
	--master-password *** get-accounts 
    --vault-id 44c0f4bc-8aca-46ac-a80a-9bd25c8f06aa --q "amazon"
```

### 11.13 Showing a specific Account by ID

#### 11.13.1 Command Line

You can show a specific Account by its data using CLI as follows:
```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password *** get-account --account-id $account_id
```

Which will show account details such as:
```json
{
  "vault_id": "73b091ba-710b-4de4-8a1e-c185e3ddd304",
  "account_id": "e60321d2-8cad-42b8-b779-4ba5b8911bbf",
  "version": 2,
  "kind": "Login",
  "label": null,
  "favorite": false,
  "risk": "High",
  "description": null,
  "username": "bob",
  "password": "**",
  "email": "bob@bitvault.com",
  "wesbite_url": "https://amazon.com",
  "category": "Shopping",
  "tags": ["Family"],
  "otp": "JBSWY3DPEHPK3PXP",
  "generated_otp": ***,
  "icon": null,
  "form_fields": {"CreditCard": "***"},
  "notes": null,
  "advisories": {
    "WeakPassword": "The password is MODERATE",
    "CompromisedPassword": "The password is compromised and found in 'Have I been Pwned' database."
  },
  "renew_interval_days": null,
  "expires_at": null,
  "credentials_updated_at": "2023-11-08T02:39:50.656771977",
  "analyzed_at": "2023-11-08T02:40:00.019194124",
  "password_min_uppercase": 1,
  "password_min_lowercase": 1,
  "password_min_digits": 1,
  "password_min_special_chars": 1,
  "password_min_length": 12,
  "password_max_length": 16,
  "created_at": "2023-11-08T02:39:50.657929166",
  "updated_at": "2023-11-08T02:40:00.020244928"
}
```

#### 11.13.2 REST API

You can show Account by its ID using REST API as follows:
```bash
curl -v -k https://localhost:8443/api/v1/vaults/$vault_id/accounts/$account_id 
	--header "Content-Type: application/json; charset=UTF-8" 
    --header "Authorization: Bearer $AUTH_TOKEN"
```

#### 11.13.3 Docker CLI

You can show an Account using Docker CLI as follows:
```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY 
	-e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass 
	-j true --master-username eddie 
	--master-password *** get-accounts 
    get-account --account-id $account_id
```

### 11.14 Updating an Account by ID

#### 11.14.1 Command Line

You can update an Account data using CLI as follows:
```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password ** update-account --vault-id $vault_id 
    --account-id $account_id --kind Logins 
    --label "My Bank" --username myuser --email "myemail@bitvault.com" 
    --password "**" --notes "Lorem ipsum dolor sit amet."
```

#### 11.14.2 REST API

You can update an Account using REST API as follows:
```bash
curl -v -k https://localhost:8443/api/v1/vaults/$vault_id/accounts/$account_id 
	--header "Content-Type: application/json; charset=UTF-8" 
    --header "Authorization: Bearer $AUTH_TOKEN"
```

#### 11.14.3 Docker CLI

You can update an Account using Docker CLI as follows:
```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY 
	-e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass 
	-j true --master-username eddie 
	--master-password *** get-accounts 
    get-account --account-id $account_id
```

### 11.15 Deleting an Account by ID

#### 11.15.1 Command Line

You can delete an Account using CLI as follows:
```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password ** delete-account --account-id $account_id
```
#### 11.15.2 REST API

You can delete Account by its ID using REST API as follows:
```bash
curl -v -k -X DELETE https://localhost:8443/api/v1/vaults/$vault_id/accounts/$account_id 
	--header "Content-Type: application/json; charset=UTF-8" 
    --header "Authorization: Bearer $AUTH_TOKEN"
```

#### 11.15.3 Docker CLI

You can delete an Account using Docker CLI as follows:
```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY 
	-e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass 
	-j true --master-username eddie 
	--master-password *** delete-account --account-id $account_id
```

### 11.16 Creating a Category

The categories are used to organize accounts in a Vault and PlexPass includes built-in categories. Here is how you can manage custom categories:

#### 11.16.1 Command Line

You can create a Category using CLI as follows:
```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password *** create-category --name "Finance"
```

#### 11.16.2 REST API

You can create a Category using REST API as follows:
```bash
curl -v -k -X POST https://localhost:8443/api/v1/categories 
	--header "Content-Type: application/json; charset=UTF-8" 
    --header "Authorization: Bearer $AUTH_TOKEN"  -d '{"name": "Banking"}'
```

#### 11.16.3 Docker CLI

You can create a Category using Docker CLI as follows:
```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY 
	-e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass 
	-j true --master-username eddie 
	--master-password *** create-category --name "Finance"
```

### 11.17 Showing Categories

#### 11.17.1 Command Line

You can show all custom Categories using CLI as follows:
```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password *** get-categories
```

#### 11.17.2 REST API

You can show all custom categories using REST API as follows:
```bash
curl -v -k https://localhost:8443/api/v1/categories 
	--header "Content-Type: application/json; charset=UTF-8" 
    --header "Authorization: Bearer $AUTH_TOKEN"
```

#### 11.17.3 Docker CLI

You can show all custom categories using Docker CLI as follows:
```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY 
	-e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass 
	-j true --master-username eddie 
	--master-password *** get-categories
```

### 11.18 Deleting a Category

#### 11.18.1 Command Line

You can delete a Category using CLI as follows:
```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password ** delete-category --name "Banking"
```

#### 11.18.2 REST API

You can delete a category using REST API as follows:
```bash
curl -v -k -X DELETE https://localhost:8443/api/v1/categories/Gaming 
	--header "Content-Type: application/json; charset=UTF-8" 
    --header "Authorization: Bearer $AUTH_TOKEN"
```

#### 11.18.3 Docker CLI

You can show all custom categories using Docker CLI as follows:
```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY 
	-e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass 
	-j true --master-username eddie 
	--master-password *** delete-category --name "Banking"
```

### 11.19 Generate Asymmetric Encryption Keys

#### 11.19.1 Command Line

You can generate asymmetric encryption keys using CLI as follows:
```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password ** generate-private-public-keys
```

You can optionally pass a seed password to generate secret and public keys. Here

#### 11.19.2 REST API

You can generate asymmetric encryption keys using REST API as follows:
```bash
curl -v -k -X POST https://localhost:8443/api/v1/encryption/generate_keys 
	--header "Content-Type: application/json; charset=UTF-8" 
    --header "Authorization: Bearer $AUTH_TOKEN" -d '{}'
```

Here is a sample output:
```json
{
  "secret_key": "7e28c2849a6316596014fea5cedf51d21236be47766b82ae35c62d2747a85bfe",
  "public_key": "04339d73ffd49da063d0518ea6661a81e92644c8571df57af3b522a7bcbcd3232f1949d2d60e3ecb096f4a5521453df30420e514c314de8c49cb6d7f5565fe8864"
}
```

#### 11.19.3 Docker CLI

You can generate asymmetric encryption keys using Docker CLI as follows:
```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY 
	-e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass 
	-j true --master-username eddie 
	--master-password *** generate-private-public-keys
```
### 11.20 Asymmetric Encryption

#### 11.20.1 Command Line

You can encrypt data using asymmetric encryption using CLI as follows:
```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password *** asymmetric-encrypt --public-key $pub 
    --in-path plaintext.dat --out-path base64-encrypted.dat
./target/release/plexpass -j true --master-username eddie 
	--master-password *** asymmetric-decrypt 
    --secret-key $prv --in-path base64-encrypted.dat --out-path plaintext-copy.dat
```
In above example, you can first generate asymmetric keys and then encrypt a file using public key and then decrypt it using private key.

#### 11.20.2 REST API

You can encrypt data using asymmetric encryption using REST API as follows:
```bash
curl -v -k -X POST https://localhost:8443/api/v1/encryption/asymmetric_encrypt/$pub 
	--header "Content-Type: application/json; charset=UTF-8" 
    --header "Authorization: Bearer $AUTH_TOKEN" 
    --data-binary "@plaintext.dat" > base64_encypted.dat

curl -v -k -X POST https://localhost:8443/api/v1/encryption/asymmetric_decrypt/$prv 
	--header "Content-Type: application/json; charset=UTF-8" 
    --header "Authorization: Bearer $AUTH_TOKEN" 
    --data-binary "@base64_encypted.dat" > plaintext-copy.dat
```
#### 11.20.3 Docker CLI

You can encrypt data using asymmetric encryption using Docker CLI as follows:

```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data 
	-v $PARENT_DIR/PlexPassData:/data -v $CWD:/files plexpass -j true 
    --master-username eddie --master-password *** asymmetric-encrypt --public-key $pub 
    --in-path plaintext.dat --out-path base64-encrypted.dat
    
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data 
	-v $PARENT_DIR/PlexPassData:/data -v $CWD:/files plexpass -j true 
    --master-username eddie --master-password *** asymmetric-decrypt 
    --secret-key $prv --in-path base64-encrypted.dat --out-path plaintext-copy.dat
```
### 11.21 Asymmetric Encryption

#### 11.21.1 Command Line

You can encrypt data using symmetric encryption using CLI as follows:
```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password *** symmetric-encrypt --secret-key $prv 
    --in-path plaintext.dat --out-path base64-encrypted.dat
./target/release/plexpass -j true --master-username eddie 
	--master-password *** asymmetric-decrypt 
    --secret-key $prv --in-path base64-encrypted.dat --out-path plaintext-copy.dat
```
In above example, you use the same symmetric key or password to encrypt and decrypt data.

#### 11.21.2 REST API

You can encrypt data using symmetric encryption using REST API as follows:
```bash
curl -v -k -X POST https://localhost:8443/api/v1/encryption/symmetric_encrypt/$prv 
	--header "Content-Type: application/json; charset=UTF-8" 
    --header "Authorization: Bearer $AUTH_TOKEN" 
    --data-binary "@plaintext.dat" > base64_encypted.dat

curl -v -k -X POST https://localhost:8443/api/v1/encryption/symmetric_decrypt/$prv 
	--header "Content-Type: application/json; charset=UTF-8" 
    --header "Authorization: Bearer $AUTH_TOKEN" 
    --data-binary "@base64_encypted.dat" > plaintext-copy.dat
```

#### 11.21.3 Docker CLI

You can encrypt data using symmetric encryption using Docker CLI as follows:

```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data 
	-v $PARENT_DIR/PlexPassData:/data -v $CWD:/files plexpass -j true 
    --master-username eddie --master-password *** symmetric-encrypt --secret-key $prv 
    --in-path plaintext.dat --out-path base64-encrypted.dat
    
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data 
	-v $PARENT_DIR/PlexPassData:/data -v $CWD:/files plexpass -j true 
    --master-username eddie --master-password *** symmetric-decrypt 
    --secret-key $prv --in-path base64-encrypted.dat --out-path plaintext-copy.dat
```

### 11.22 Importing and Exporting Accounts Data

#### 11.22.1 Command Line

Given a CSV file with accounts data such as:
```csv 
Type,name,url,username,password,note,totp,category
Login,Youtube,https://www.youtube.com/,youlogin,youpassword,tempor incididunt ut labore et,,
Login,Amazon,https://www.amazon.com/,amlogin1,ampassword1,sit amet, consectetur adipiscing,,
Login,Bank of America ,https://www.boa.com/,mylogin3,mypassword3,Excepteur sint occaecat cupidatat non,,
Login,Twitter,https://www.twitter.com/,mylogin3,mypassword3,eiusmod tempor incididunt ut,,
Login,AT&T,https://www.att.com/,mylogin4,mypassword4,mynote4,,
Secure Note,Personal Note name,,,,My Secure Note,,
```

You can import accounts data from a CSV file using CLI as follows:
```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password *** import-accounts --vault-id $vault_id 
    --in-path accounts.csv
```
You can also export accounts data as follows:
```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password *** export-accounts --vault-id $vault_id 
    --password *** --out-path encrypted-accounts.dat
```
In above example, the exported data will be encrypted with given password and you can use symmetric encryption to decrypt it or import it later as follows:

```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password *** import-accounts --vault-id $vault_id 
    --password ** --in-path encrypted-accounts.dat
```
#### 11.22.2 REST API

You can import accounts data from a CSV file using REST API as follows:
```bash
curl -v -k -X POST https://localhost:8443/api/v1/vaults/$vault_id/import 
	--header "Content-Type: application/json; charset=UTF-8" 
    --header "Authorization: Bearer $AUTH_TOKEN" 
    --data-binary "@accounts.csv" -d '{}'
```
You can then export accounts data as an encrypted CSV file as follows:

```bash
curl -v -k --http2 --sslv2 -X POST "https://localhost:8443/api/v1/vaults/$vault_id/export" 
	--header "Content-Type: application/json; charset=UTF-8" 
    --header "Authorization: Bearer $AUTH_TOKEN" -d '{"password": "**"}' > encrypted_csv.dat
```
And then import it back later as follows:

```bash
curl -v -k -X POST https://localhost:8443/api/v1/vaults/$vault_id/import 
	--header "Content-Type: application/json; charset=UTF-8" 
    --header "Authorization: Bearer $AUTH_TOKEN" --data-binary "@encrypted_csv.dat" 
    -d '{"password": "***"}'
```

#### 11.22.3 Docker CLI

You can import accounts data from a CSV file using Docker CLI as follows:

```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data 
	-v $PARENT_DIR/PlexPassData:/data -v $CWD:/files plexpass 
    -j true --master-username frank --master-password *** import-accounts 
    --vault-id $vault_id --in-path /files/accounts.csv
```
And export it without password as follows:

```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data 
	-v $PARENT_DIR/PlexPassData:/data -v $CWD:/files plexpass -j true 
    --master-username frank --master-password *** export-accounts 
    --vault-id $vault_id --out-path /files/plaintext.csv
```
### 11.23 Generating Strong Password

#### 11.23.1 Command Line

You can generate a strong password using CLI as follows:

```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password ** generate-password
```
That generates a memorable or random password such as:
```json
{"password": "**"}
```

#### 11.23.2 REST API

You can generate a strong password using REST API as follows:
```bash
curl -v -k --header "Content-Type: application/json; charset=UTF-8" 
	--header "Authorization: Bearer $AUTH_TOKEN" 
    https://localhost:8443/api/v1//password/memorable -d '{}'
    
curl -v -k --header "Content-Type: application/json; charset=UTF-8" 
	--header "Authorization: Bearer $AUTH_TOKEN" 
    https://localhost:8443/api/v1//password/random -d '{}'
```

You can optionally specify password policies with following properties:
```json
-d '{
  "password_min_uppercase": 1,
  "password_min_lowercase": 1,
  "password_min_digits": 1,
  "password_min_special_chars": 1,
  "password_min_length": 12,
  "password_max_length": 16,
}'
```

#### 11.23.3 Docker CLI

You can generate a strong password using Docker CLI as follows:

```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data 
	-v $PARENT_DIR/PlexPassData:/data plexpass -j true --master-username frank 
    --master-password ** generate-password
```

### 11.24 Checking if a Password is Compromised

#### 11.24.1 Command Line

You can check if a password is compromised using CLI as follows:

```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password ** password-compromised --password **
```
That returns as a flag as follows:

```json
{"compromised":true}
```

#### 11.24.2 REST API

You can check if a password is compromised using REST API as follows:
```bash
curl -v -k --header "Content-Type: application/json; charset=UTF-8" 
	--header "Authorization: Bearer $AUTH_TOKEN" 
    https://localhost:8443/api/v1/password/***/compromised
```

#### 11.24.3 Docker CLI

You can check if a password is compromised using Docker CLI as follows:
```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data 
	-v $PARENT_DIR/PlexPassData:/data -v $CWD:/files plexpass 
    -j true --master-username frank --master-password *** password-compromised --password **
```

### 11.25 Checking Strength of a Password

#### 11.25.1 Command Line

You can check strength of a password using CLI as follows:

```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password ** password-strength --password **
```

That returns as password properties as follows:

```json
{
  "strength": "MODERATE",
  "entropy": 42.303957463269825,
  "uppercase": 0,
  "lowercase": 10,
  "digits": 0,
  "special_chars": 0,
  "length": 10
}
```

#### 11.25.2 REST API

You can check strength of a password using REST API as follows:
```bash
curl -v -k --header "Content-Type: application/json; charset=UTF-8" 
	--header "Authorization: Bearer $AUTH_TOKEN" 
    https://localhost:8443/api/v1/password/**/strength
```

#### 11.25.3 Docker CLI

You can check strength of a password using Docker CLI as follows:
```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data 
	-v $PARENT_DIR/PlexPassData:/data plexpass -j true --master-username frank 
    --master-password *** password-strength --password ***
```

### 11.26 Checking if Email is Compromised

#### 11.26.1 Command Line

PlexPass integrates with [https://haveibeenpwned.com/](https://haveibeenpwned.com/) and you can check if an emaill or website is compromised if you have an API key from the website. Here is how you can check if email is compromised using CLI as follows:

```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password Cru5h_rfIt:v_Bk email-compromised 
    --email myemail@bitvault.com
```

This would return an error if you haven’t configured the API key, e.g.

```bash
could not check password: Validation { message: "could not find api key for HIBP", reason_code: None }
```

#### 11.26.2 REST API

You can check if an email is compromised using REST API as follows:

```bash
curl -v -k --header "Content-Type: application/json; charset=UTF-8" 
	--header "Authorization: Bearer $AUTH_TOKEN" 
    https://localhost:8443/api/v1/emails/email/compromised
```

#### 11.26.3 Docker CLI

You can check if an email is compromised using Docker CLI as follows:

```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data 
	-v $PARENT_DIR/PlexPassData:/data plexpass -j true --master-username frank 
    --master-password ** email-compromised --email myemail@mail.com
```

### 11.27 Analyzing Passwords for a Vault

#### 11.27.1 Command Line

PlexPass integrates with [https://haveibeenpwned.com/](https://haveibeenpwned.com/) and checks for strength, similarity, and password reuse. Here is how you can analyze all passwords in a vault using CLI as follows:

```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password ** analyze-vault-passwords --vault-id $vault_id
```

This would return return summary of the analysis:
```json
{
  "total_accounts": 35,
  "count_strong_passwords": 1,
  "count_moderate_passwords": 20,
  "count_weak_passwords": 14,
  "count_healthy_passwords": 1,
  "count_compromised": 32,
  "count_reused": 29,
  "count_similar_to_other_passwords": 22,
  "count_similar_to_past_passwords": 0
}
```

Each acount will be updated with advisories based on the analysis.

#### 11.27.2 REST API

You can analyze all accounts in a Vault using REST API as follows:

```bash
curl -v -k -X POST --header "Content-Type: application/json; charset=UTF-8" 
	--header "Authorization: Bearer $AUTH_TOKEN" 
    https://localhost:8443/api/v1/vaults/$vault_id/analyze_passwords
```

#### 11.27.3 Docker CLI

You can analyze all accounts in a Vault using Docker CLI as follows:
```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data 
	-v $PARENT_DIR/PlexPassData:/data plexpass -j true --master-username frank 
    --master-password ** analyze-vault-passwords --vault-id $vault_id
```

### 11.28 Analyzing Passwords for all Vaults

#### 11.28.1 Command Line

Here is how you can analyze passwords in all vaults using CLI as follows:

```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password ** analyze-all-vaults-passwords
```

This would return return summary of the analysis:
```json
{ 
  "vault-id" :{
    "total_accounts": 35,
    "count_strong_passwords": 1,
    "count_moderate_passwords": 20,
    "count_weak_passwords": 14,
    "count_healthy_passwords": 1,
    "count_compromised": 32,
    "count_reused": 29,
    "count_similar_to_other_passwords": 22,
   "count_similar_to_past_passwords": 0
 }
}
```

Each acount will be updated with advisories based on the analysis.

#### 11.28.2 REST API

You can analyze accounts in all Vaults using REST API as follows:

```bash
curl -v -k -X POST --header "Content-Type: application/json; charset=UTF-8" 
	--header "Authorization: Bearer $AUTH_TOKEN" 
    https://localhost:8443/api/v1/password/analyze_all_passwords
```

#### 11.28.3 Docker CLI

You can analyze accounts in all Vaults using Docker CLI as follows:

```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data 
	-v $PARENT_DIR/PlexPassData:/data plexpass -j true --master-username frank 
    --master-password ** analyze-all-vaults-passwords
```

### 11.29 Searching Usernames

PlexPass allows searching usernames for sharing data, however by default this feature is only allowed if accessed from a trusted local network.

#### 11.29.1 Command Line

You can search usernames using CLI as follows:

```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password ** search-usernames --q ali
```

#### 11.29.2 REST API

You can search usernames using REST API as follows:

```bash
curl -v -k --header "Content-Type: application/json; charset=UTF-8" 
	--header "Authorization: Bearer $AUTH_TOKEN" https://localhost:8443/api/v1/usernames?q=ali
```

#### 11.29.3 Docker CLI

You can search usernames using Docker CLI as follows:

```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e DATA_DIR=/data 
	-v $PARENT_DIR/PlexPassData:/data plexpass -j true --master-username frank 
    --master-password *** search-usernames --q ali
```
### 11.30 Sharing a Vault with another User

PlexPass allows sharing a vault with another user for read-only or read/write access to view or edit all accounts in the Vault.

#### 11.30.1 Command Line

You can share a Vault with another user using CLI as follows:

```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password *** share-vault --vault-id $vault_id --target-username frank
```


Vault and Account sharing within the system leverages public key infrastructure (PKI) for secure data exchange. This process involves encrypting the encryption keys of the Vault using the intended recipient user’s public key. A message containing this encrypted data is then sent to the recipient. Upon the recipient user’s next sign-in, this data is decrypted and subsequently re-encrypted using the recipient’s public key, ensuring secure access and transfer of information.

#### 11.30.2 REST API

You can share a Vault with another user using REST API as follows:

```bash
curl -v -k --header "Content-Type: application/json; charset=UTF-8" 
	--header "Authorization: Bearer $AUTH_TOKEN" 
    https://localhost:8443/api/v1/vaults/$vault_id/share 
    -d '{"target_username": "frank"}'
```

#### 11.30.3 Docker CLI

You can search usernames using Docker CLI as follows:

```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e RUST_BACKTRACE=1 
	-e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass -j true 
    --master-username frank --master-password ** share-vault 
    --vault-id $vault_id --target-username charlie
```

### 11.31 Sharing an Account with another User

PlexPass allows sharing an account by sending an encrypted account data, which uses target user’s public key so that target user can decrypt it.

#### 11.31.1 Command Line

You can share an Account with another user using CLI as follows:

```bash
./target/release/plexpass -j true --master-username eddie 
	--master-password *** share-account --vault-id $vault_id 
    --account-id $account_id --target-username frank
```

#### 11.31.2 REST API

You can share an Account with another user using REST API as follows:

```bash
curl -v -k --header "Content-Type: application/json; charset=UTF-8" 
	--header "Authorization: Bearer $AUTH_TOKEN" 
    https://localhost:8443/api/v1/vaults/$vault_id/accounts/$account_id/share 
    -d '{"target_username": "frank"}'
```

#### 11.31.3 Docker CLI

You can share an Account with another using Docker CLI as follows:

```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e RUST_BACKTRACE=1 
	-e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass -j true 
    --master-username frank --master-password ** share-vault 
    --vault-id $vault_id --target-username charlie
```

### 11.32 Generating OTP code

PlexPass allows generating OTP code based on base-32 secret.

#### 11.32.1 Command Line

You can generate otp for a particular account using based on CLI as follows:

```bash
./target/release/plexpass -j true --master-username eddie --master-password *** generate-otp --account-id $account_id
```

or using secret as follows:

```bash
./target/release/plexpass -j true --master-username eddie --master-password *** generate-otp --otp-secret "JBSWY3DPEHPK3PXP"
```

#### 11.32.2 REST API

The OTP will be included with account API if you have previously setup otp-secret, e.g.,

```bash
curl -v -k --header "Content-Type: application/json; charset=UTF-8" 
	--header "Authorization: Bearer $AUTH_TOKEN" 
    https://localhost:8443/api/v1/vaults/$vault_id/accounts/$account_id
```

or, generate otp using a secret

```bash
curl -v -k --header "Content-Type: application/json; charset=UTF-8" 
	--header "Authorization: Bearer $AUTH_TOKEN" 
    https://localhost:8443/api/v1/otp/generate -d '{"otp_secret": "***"}'
```

#### 11.32.3 Docker CLI

You can generate otp for a particular account using based on Docker CLI as follows:

```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e RUST_BACKTRACE=1 
	-e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass -j true --master-username eddie --master-password *** generate-otp --account-id $account_id
```

or using secret as follows:

```bash
docker run -e DEVICE_PEPPER_KEY=$DEVICE_PEPPER_KEY -e RUST_BACKTRACE=1 
	-e DATA_DIR=/data -v $PARENT_DIR/PlexPassData:/data plexpass -j true  --master-username eddie --master-password *** generate-otp --otp-secret "JBSWY3DPEHPK3PXP"
```

### 11.33 Security Dashboad and Auditing

The PlexPass web application includes a security dashboard to monitor health of all passwords and allows users to view audit logs for all changes to their accounts, e.g.,

![](https://weblog.plexobject.com/images/dashboard.png)

Security Dashboard

![](https://weblog.plexobject.com/images/audit.png)

12.0 Summary
------------

The design principles and architectural framework outlined above showcase PlexPass’s advanced capabilities in password management, setting it apart from conventional cloud-based password managers. The key advantages of PlexPass include:

1.  **End-to-End Encryption and Zero-Knowledge Architecture**: By encrypting all data with strong algorithms and ensuring that decryption happens only on the user’s device, PlexPass provides a high level of security. The zero-knowledge architecture means that it assumes no trust when accessing secured user data.
2.  **Local Data Storage and Management**: With no reliance on cloud storage, PlexPass reduces the risk of data breaches and privacy concerns associated with cloud services.
3.  **Advanced Cryptographic Techniques**: PlexPass’s use of Argon2 for password hashing, AES-256 for symmetric encryption, and ECC for asymmetric encryption, coupled with envelope encryption, positions it at the forefront of modern cryptographic practices.
4.  **User-Friendly Experience with Strong Security Practices**: Despite its focus on security, PlexPass promises a great user experience through its command-line tool and web-based UI.
5.  **Open Source with Regular Updates**: PlexPass is open-source that allows for community scrutiny, which can lead to the early detection and rectification of vulnerabilities.
6.  **Physical Security Considerations and Data Breach Alerts**: PlexPass analyzes passwords for breaches, weak strength, similarity with other passwords and provides a dashboard for monitoring password security.
7.  **Multi-Device and Secure Sharing Features**: The ability to share passwords securely with nearby trusted devices without cloud risks, and the support for multi-device use, make it versatile and family-friendly.
8.  **Strong Master Password and Password Generation**: Encouraging strong master passwords and providing tools for generating robust passwords further enhance individual account security.
9.  **Detailed Domain Model with Advanced Data Storage and Network Communication**: PlexPass’s detailed model covers all aspects of password management and security, ensuring thorough protection at each level.
10.  **Local Control and Privacy**: With PlexPass, all data is stored locally, providing users with full control over their password data. This is particularly appealing for those who are concerned about privacy and don’t want their sensitive information stored on a cloud server.
11.  **Customization and Flexibility**: PlexPass can be customized to fit specific needs and preferences. Users who prefer to have more control over the configuration and security settings may find PlexPass more flexible than cloud-based solutions.
12.  **Cost Control**: Hosting your own password manager might have cost benefits, as you avoid ongoing subscription fees associated with many cloud-based password managers.
13.  **Transparency and Trust**: PlexPass is open-source, users can inspect the source code for any potential security issues, giving them a higher degree of trust in the application.
14.  **Reduced Attack Surface**: By not relying on cloud connectivity, offline managers are not susceptible to online attacks targeting cloud storage.
15.  **Control over Data**: Users have complete control over their data, including how it’s stored and backed up.
16.  **Potentially Lower Risk of Service Shutdown**: Since the data is stored locally, the user’s access to their passwords is not contingent on the continued operation of a third-party service.
17.  **Multi-Factor Authentication**: PlexPass supports Multi-Factor Authentication based on One-Time-Passwords (OTP) and other standards.

PlexPass plans to incorporate standards such as FIDO, WebAuthN, and YubiKey for authentication enhances security beyond just password protection, aligning with the latest industry standards for secure access. In summary, PlexPass, with its extensive features, represents a holistic and advanced approach to password management. You can download it freely from [https://github.com/bhatti/PlexPass](https://github.com/bhatti/PlexPass) and provide your feedback.
