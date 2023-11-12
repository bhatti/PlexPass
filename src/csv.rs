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
    name: String, // label
    #[serde(alias = "website")]
    url: Option<String>,
    username: Option<String>,
    password: Option<String>,
    email: Option<String>,
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
}

impl CSVRecord {
    pub(crate) fn new(account: &Account) -> Self {
        Self {
            type_: account.details.kind.to_string(),
            name : account.details.label.clone().unwrap_or("".into()),
            url: account.details.url.clone(),
            username: account.details.username.clone(),
            email: account.details.email.clone(),
            password: account.credentials.password.clone(),
            description: account.details.description.clone(),
            note: account.credentials.notes.clone(),
            otp: account.credentials.otp.clone(),
            category: account.details.category.clone(),
            tags: Some(account.details.tags.clone().join(";")),
            icon: account.details.icon.clone(),
            renew_interval_days: account.details.renew_interval_days,
            expires_at: account.details.expires_at.map(|expires_at| format!("{}", expires_at.format("2015-09-05"))),
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
        account.details.url = self.url.clone();
        account.details.category = self.category.clone();
        if let Some(tags) = &self.tags {
            account.details.tags = tags.as_str().split("[,;]").map(|s|s.to_string()).collect::<Vec<String>>();
        }
        account.details.icon = self.icon.clone();
        account.details.renew_interval_days = self.renew_interval_days;
        if let Some(expires_at) = &self.expires_at {
            account.details.expires_at = safe_parse_str_date(expires_at);
        }

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
    use crate::csv::CSVRecord;

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
}