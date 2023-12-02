use std::collections::HashMap;
use std::io::Write;
use csv::{ReaderBuilder};
use serde::{Deserialize, Serialize};
use crate::domain::models::{Account, AccountKind, PassResult, PasswordPolicy};
use crate::utils::safe_parse_str_date;

/// DashlineRecord for importing data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CSVRecord {
    #[serde(rename = "Type", alias = "kind", alias = "type")]
    type_: String,
    #[serde(alias = "label", alias = "title")]
    name: String,
    // label
    #[serde(alias = "website", alias = "url")]
    website_url: Option<String>,
    username: Option<String>,
    password: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    address: Option<String>,
    description: Option<String>,
    #[serde(alias = "notes", alias = "secure_notes")]
    note: Option<String>,
    category: Option<String>,
    tags: Option<String>,
    #[serde(alias = "totp")]
    otp: Option<String>,
    icon: Option<String>,
    renew_interval_days: Option<i32>,
    expires_at: Option<String>,
    due_at: Option<String>,
    favorite: Option<bool>,
}

impl CSVRecord {
    pub(crate) fn new(account: &Account) -> Self {
        Self {
            type_: account.details.kind.to_string(),
            name: account.details.label.clone().unwrap_or("".into()),
            website_url: account.details.website_url.clone(),
            username: account.details.username.clone(),
            email: account.details.email.clone(),
            phone: account.details.phone.clone(),
            address: account.details.address.clone(),
            password: account.credentials.password.clone(),
            description: account.details.description.clone(),
            note: account.credentials.notes.clone(),
            otp: account.credentials.otp.clone(),
            category: account.details.category.clone(),
            tags: Some(account.details.tags.clone().join(";")),
            icon: account.details.icon.clone(),
            renew_interval_days: account.details.renew_interval_days,
            expires_at: account.details.expires_at.map(|expires_at| format!("{}", expires_at.format("%Y-%m-%d %H:%M:%S"))),
            due_at: account.details.due_at.map(|due_at| format!("{}", due_at.format("%Y-%m-%d %H:%M:%S"))),
            favorite: Some(account.details.favorite),
        }
    }

    //Type,name,url,username,password,note,totp,category
    //Login,Website name,https://www.website.com/,mylogin,mypassword,mynote,,
    //Secure Note,Note name,,,,My Secure Note,,
    pub fn parse(data: &[u8]) -> PassResult<Vec<CSVRecord>> {
        let mut rdr = ReaderBuilder::new().flexible(true).from_reader(data);
        let mut records = vec![];
        for result in rdr.deserialize() {
            let record: CSVRecord = result?;
            records.push(record);
        }
        Ok(records)
    }

    pub fn write<W: Write>(recs: Vec<CSVRecord>, writer: W, header: bool) -> PassResult<()> {
        let mut wtr = csv::WriterBuilder::new().has_headers(header).from_writer(writer);
        for rec in recs {
            wtr.serialize(rec)?;
        }
        wtr.flush()?;
        Ok(())
    }
    pub fn to_account(&self, vault_id: &str) -> Account {
        let mut account = Account::new(vault_id,
                                       AccountKind::from(self.type_.clone().as_str()));
        account.details.kind = AccountKind::from(self.type_.as_str());
        account.details.label = Some(self.name.clone());
        account.details.description = self.description.clone();
        account.details.username = self.username.clone();
        account.details.email = self.email.clone();
        account.details.phone = self.phone.clone();
        account.details.address = self.address.clone();
        account.details.website_url = self.website_url.clone();
        account.details.category = self.category.clone();
        if let Some(tags) = &self.tags {
            account.details.tags = tags.as_str().split("[,;]").map(|s| s.to_string()).collect::<Vec<String>>();
        }
        account.details.icon = self.icon.clone();
        account.details.renew_interval_days = self.renew_interval_days;
        if let Some(expires_at) = &self.expires_at {
            account.details.expires_at = safe_parse_str_date(expires_at);
        }
        if let Some(due_at) = &self.due_at {
            account.details.due_at = safe_parse_str_date(due_at);
        }
        account.details.favorite = self.favorite.unwrap_or(false);

        account.credentials.password = self.password.clone();
        account.credentials.form_fields = HashMap::new();
        account.credentials.notes = self.note.clone();

        let password_policy = PasswordPolicy::new();
        account.credentials.password_policy = password_policy;
        account
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use crate::csv::CSVRecord;
    use crate::domain::models::{Account, AccountKind};

    #[test]
    fn test_should_parse_csv() {
        let data = r#"
Type,name,url,username,password,note,totp,category
Login,Website name,https://www.website.com/,mylogin,mypassword,mynote,,
Secure Note,Note name,,,,My Secure Note,,
"#;
        let recs = CSVRecord::parse(data.as_bytes()).unwrap();
        assert_eq!(2, recs.len());
    }

    #[test]
    fn test_should_serialize_csv() {
        let data = r#"
type,name,url,username,password,note,totp,category
Login,Website name,https://www.website.com/,mylogin,mypassword,mynote,,
Login,Amazon      ,https://www.amazon.com/,mylogin1,mypassword1,mynote1,,
Login,Bank        ,https://www.bank.com/  ,mylogin2,mypassword2,mynote2,,
Login,Twitter     ,https://www.twitter.com/,mylogin3,mypassword3,mynote3,,
Login,Phone,https://www.phone.com/,mylogin4,mypassword4,mynote4,,
Login,Insurance   ,https://www.insurance.com/,mylogin5,mypassword5,mynote5,,
Secure Note,Note name,,,,My Secure Note,,
Secure Note,Note name1,,,,My Secure Note1,,
Secure Note,Note name2,,,,My Secure Note2,,
Secure Note,Note name3,,,,My Secure Note3,,
Secure Note,Note name4,,,,My Secure Note4,,
Secure Note,Note name5,,,,My Secure Note5,,
Login,Mortgage    ,https://www.mortgage.com/,mylogin5,mypassword5,mynote5,,
Login,License     ,https://www.dol.com/,mylogin6,mypassword6,mynote6,,
"#;
        let recs = CSVRecord::parse(data.as_bytes()).unwrap();
        assert_eq!(14, recs.len());
        let mut buf = Vec::new();
        CSVRecord::write(recs, &mut buf, true).unwrap();
        let loaded = CSVRecord::parse(&buf).unwrap();
        assert_eq!(14, loaded.len());
    }

    #[test]
    fn test_should_serialize_account() {
        let mut account = Account::new("vault0", AccountKind::Logins);
        account.details.label = Some("my label".into());
        account.details.version = 10;
        account.details.favorite = true;
        account.details.username = Some("test1".into());
        account.credentials.password = Some("pass".into());
        account.credentials.notes = Some("my notes".into());
        account.details.email = Some("email@mail.cc".into());
        account.details.website_url = Some("https://mail.cc".into());
        account.details.category = Some("Contacts".into());
        account.details.tags = vec!["Personal".to_string()];
        account.details.renew_interval_days = Some(3);
        account.details.expires_at = Some(Utc::now().naive_utc());
        account.details.due_at = Some(Utc::now().naive_utc());
        let csv_rec = CSVRecord::new(&account);
        let account_json = serde_json::to_string(&csv_rec).unwrap();
        let des_csv_rec: CSVRecord = serde_json::from_str(&account_json).unwrap();
        let des_account = des_csv_rec.to_account(&account.vault_id);
        assert_eq!(account.vault_id, des_account.vault_id);
        assert_ne!(account.details.account_id, des_account.details.account_id); // should not be equal
        assert_ne!(account.details.version, des_account.details.version); // should not be equal
        assert_eq!(account.details.label, des_account.details.label);
        assert_eq!(account.details.kind, des_account.details.kind);
        assert_eq!(account.details.favorite, des_account.details.favorite);
        assert_eq!(account.details.risk, des_account.details.risk);
        assert_eq!(account.details.username, des_account.details.username);
        assert_eq!(account.details.email, des_account.details.email);
        assert_eq!(account.details.category, des_account.details.category);
        assert_eq!(account.details.website_url, des_account.details.website_url);
        assert_eq!(account.credentials.password, des_account.credentials.password);
        assert_eq!(account.credentials.notes, des_account.credentials.notes);
        assert_eq!(account.details.tags, des_account.details.tags);
        assert_eq!(account.details.renew_interval_days, des_account.details.renew_interval_days);
        assert_eq!(account.details.expires_at.unwrap().format("%Y-%m-%d").to_string(),
                   des_account.details.expires_at.unwrap().format("%Y-%m-%d").to_string());
        assert_eq!(account.details.due_at.unwrap().format("%Y-%m-%d").to_string(),
                   des_account.details.due_at.unwrap().format("%Y-%m-%d").to_string());
    }
}
