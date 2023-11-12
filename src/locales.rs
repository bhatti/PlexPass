use fluent::{FluentArgs, FluentValue};
use fluent_resmgr::resource_manager::ResourceManager;
use std::{fs, io};
use std::path::PathBuf;
use fluent_langneg::{negotiate_languages, NegotiationStrategy};
use unic_langid::LanguageIdentifier;
use crate::domain::models::PassResult;

/// This helper function allows us to read the list
/// of available locales by reading the list of
/// directories in `./resources`.
///
/// It is expected that every directory inside it
/// has a name that is a valid BCP47 language tag.
fn get_available_locales() -> Result<Vec<LanguageIdentifier>, io::Error> {
    let mut locales = vec![];
    let res_path = PathBuf::from("resources");
    let res_dir = fs::read_dir(res_path)?;
    for entry in res_dir.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(name) = path.file_name() {
                if let Some(name) = name.to_str() {
                    let langid: LanguageIdentifier = name.parse().expect("Parsing failed.");
                    locales.push(langid);
                }
            }
        }
    }
    Ok(locales)
}

pub fn safe_localized_message(
    message_id: &str,
    args: Option<&[&str]>,
) -> String {
    localized_message("en-US", message_id, args).unwrap_or(message_id.to_string())
}

fn localized_message<'a>(
    locale: &'a str,
    message_id: &'a str,
    args: Option<&[&str]>,
) -> PassResult<String> {
    let resources = vec!["main.ftl".into(), "errors.ftl".into()];
    let default_locale: LanguageIdentifier = "en-US".parse()?;
    let available = get_available_locales()?;
    let requested: Vec<LanguageIdentifier> = locale.split(',')
            .map(|s| s.parse().expect("parsing locale failed"))
            .collect();
    let resolved_locales = negotiate_languages(
        &requested,
        &available,
        Some(&default_locale),
        NegotiationStrategy::Filtering,
    );

    let mgr = ResourceManager::new("resources/{locale}/{res_id}".into());
    let bundle = mgr
        .get_bundle(
            resolved_locales.into_iter().map(|s| s.to_owned()).collect(),
            resources,
        );

    let mut fl_args = FluentArgs::new();
    if let Some(args) = args {
        for i in (0..args.len()-1).step_by(2) {
            fl_args.set(args[i], FluentValue::from(args[i+1]));
        }
    }
    let mut errors = vec![];
    let msg = bundle.get_message(message_id).expect("Message doesn't exists");
    let pattern = msg.value().expect("Message should have a value");
    let value = bundle.format_pattern(pattern, Some(&fl_args), &mut errors);
    Ok(value.into_owned())
}

#[cfg(test)]
mod tests {
    use crate::locales::{localized_message, safe_localized_message};

    #[tokio::test]
    async fn test_should_get_welcome_message() {
        let msg = safe_localized_message("welcome", None);
        assert!(msg.contains("Welcome to PlexPass"));
    }

    #[tokio::test]
    async fn test_should_get_message() {
        let msg = safe_localized_message("hello", Some(&["name", "Sam", "place", "World"]));
        assert!(msg.contains("Sam"));
        assert!(msg.contains("World"));
    }

    #[tokio::test]
    async fn test_should_get_welcome_message_with_unknown_locale() {
        let msg = localized_message("de", "welcome", None).unwrap();
        assert!(msg.contains("Welcome to PlexPass"));
    }

    #[tokio::test]
    async fn test_should_get_error_message() {
        let msg = safe_localized_message("auth-error", None);
        assert!(msg.contains("credentials"));
    }
}
