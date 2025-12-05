/*
 * xml.h - Minimal XML parser for API responses
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef DDNS_XML_H
#define DDNS_XML_H

#include <stdbool.h>

/* Find element content between opening and closing tags */
char *xml_find_element(const char *xml, const char *tag);

/* Find attribute value within a tag */
char *xml_find_attribute(const char *xml, const char *tag, const char *attr);

/* Decode basic XML entities (&amp; &lt; &gt; &quot; &apos;) */
char *xml_decode_entities(const char *str);

/* Check if response indicates success based on code tag */
bool xml_check_success(const char *xml, const char *code_tag, const char *success_code);

#endif /* DDNS_XML_H */
