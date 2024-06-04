use openidconnect::{
    core::{CoreClient, CoreProviderMetadata},
    reqwest::async_http_client,
    ClientId, IssuerUrl, ResourceOwnerPassword, ResourceOwnerUsername,
};

use openidconnect::OAuth2TokenResponse;

use anyhow::Result;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ReallianceId {
    pub oidc_application: String,
    pub oidc_client_id: String,
    pub oidc_user: String,
    pub oidc_pass: String,
}

impl ReallianceId {
    pub async fn token(self) -> Result<String> {
        let provider_metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(format!(
                "https://id.realliance.net/application/o/{}/",
                self.oidc_application
            ))?,
            async_http_client,
        )
        .await?;

        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(self.oidc_client_id),
            None,
        );

        Ok(client
            .exchange_password(
                &ResourceOwnerUsername::new(self.oidc_user),
                &ResourceOwnerPassword::new(self.oidc_pass),
            )
            .request_async(async_http_client)
            .await?
            .access_token()
            .secret()
            .clone())
    }
}
