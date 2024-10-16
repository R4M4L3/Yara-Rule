rule NetflixReport
{
    meta:
    description = "squatting campaign used by threat actors to target the media sector. The campaign has a global scope assumingly luring users into giving away their login credentials.Threat Type"
    Author = "Sakarie Sa'ad Osman"
    date = "21-05-2024"

    strings:
        $domain1 = "my-membership-netflix.com"
        $domain1 = "reactivate-account-netfiix.com"
        $domain1 = "supportsnetflix.com"



    condition:
        any of them        

}