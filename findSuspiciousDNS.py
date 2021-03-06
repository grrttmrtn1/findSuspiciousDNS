import piholeSqlite
import anomaliCheck
import logging
import logging.handlers

def normalizePiholeDomains(sites):
    fullsites =[]
    for row in sites:
        site = str (''.join (row))
        sitesplit = site.split('.')
        fullsite = sitesplit[len (sitesplit) - 2] + '.' + sitesplit[len (sitesplit) - 1]
        fullsites.append(fullsite)
    return list (dict.fromkeys (fullsites))

#default pihole db - "/etc/pihole/pihole-FTL.db"
#my sql query - "select distinct domain from queries where timestamp >= strftime('%s', 'now', 'localtime', 'start of day', 'utc');"
pihole = piholeSqlite.piholeSqlite("","")
connection = pihole.create_connection()
sites = pihole.runQuery(connection)

fullsites = normalizePiholeDomains(sites)

anomali = anomaliCheck.anomaliCheck('','' ,'', '')
#myquery - "itype = 'suspicious_domain' OR itype = 'phish_domain' OR itype='phish_url'"
domains = anomali.export_observables("")

parsedDomains = anomali.parseDomains(domains)
my_logger = logging.getLogger('findSuspiciousDomains')
my_logger.setLevel(logging.WARN)
#address = ('host', port)
handler = logging.handlers.SysLogHandler(address = ('', ))
my_logger.addHandler(handler)

for site in fullsites:
     if site in parsedDomains:
            print(site)
            my_logger.warn('Site found in DNS lookups matches a domain in Anomali - ' + site)
