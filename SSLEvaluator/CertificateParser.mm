//
//  CertificateParser.m
//  SSLEvaluator
//
//  Created by Daniel Bates on 16/05/2021.
//

#import "CertificateParser.hpp"
#include <iostream>
#include <sstream>
#include <vector>
#include <map>
#include <string>

@implementation CertificateParser

-(instancetype)initWithCertificate:(X509 *)certificate
{
   
    self = [super init];
    if (self) {
        [self setCert:certificate];
    }
        
    return self;
    
}

-(int)getX509VersionNumber
{
    return (int)X509_get_version([self cert]) +1;
}

-(NSString*) getSerial
{
    std::string serial = asn1int(X509_get_serialNumber([self cert]));
    return [NSString stringWithCString:serial.c_str() encoding:NSUTF8StringEncoding];
    
}

-(NSString *)getCommonName
{
    return [NSString stringWithCString:X509_NAME_oneline(X509_get_subject_name([self cert]), NULL, 0) encoding:NSUTF8StringEncoding];
}

-(NSString*)getThumbprint
{
    
    static const char hexbytes[] = "0123456789ABCDEF";
    unsigned int md_size;
    unsigned char md[EVP_MAX_MD_SIZE];
    const EVP_MD * digest = EVP_get_digestbyname("sha1");
    X509_digest([self cert], digest, md, &md_size);
    std::stringstream ashex;
    for(int pos = 0; pos < md_size; pos++)
    {
        ashex << hexbytes[ (md[pos]&0xf0)>>4 ];
        ashex << hexbytes[ (md[pos]&0x0f)>>0 ];
    }
    
    std::string str = ashex.str();
    
    return [NSString stringWithCString:str.c_str() encoding:NSUTF8StringEncoding];

}

-(NSString *)getIssuer
{
    X509* cert = [self cert];
    std::string str = issuer_one_line(cert);
    return [NSString stringWithCString:str.c_str() encoding:NSUTF8StringEncoding];
}

-(NSMutableArray*) getSubjectAltNames
{
    NSMutableArray* array = [[NSMutableArray alloc]init];
    GENERAL_NAMES* subjectAltNames = (GENERAL_NAMES*)X509_get_ext_d2i([self cert], NID_subject_alt_name, NULL, NULL);
    for (int i = 0; i < sk_GENERAL_NAME_num(subjectAltNames); i++)
    {
        GENERAL_NAME* gen = sk_GENERAL_NAME_value(subjectAltNames, i);
        if (gen->type == GEN_URI || gen->type == GEN_DNS || gen->type == GEN_EMAIL)
        {
            ASN1_IA5STRING *asn1_str = gen->d.uniformResourceIdentifier;
            std::string san = std::string( (char*)ASN1_STRING_data(asn1_str), ASN1_STRING_length(asn1_str) );
            //list.push_back( san );
            [array addObject:[NSString stringWithCString:san.c_str() encoding:NSUTF8StringEncoding]];
        }
        else if (gen->type == GEN_IPADD)
        {
            unsigned char *p = gen->d.ip->data;
            if(gen->d.ip->length == 4)
            {
                std::stringstream ip;
                ip << (int)p[0] << '.' << (int)p[1] << '.' << (int)p[2] << '.' << (int)p[3];
                std::string ipStr = ip.str();
                [array addObject:[NSString stringWithCString:ipStr.c_str() encoding:NSUTF8StringEncoding]];
            }
        }
       
    }
    GENERAL_NAMES_free(subjectAltNames);
    return array;
}

-(NSString*)getValidFrom
{
    std::string beginTime = asn1datetime_isodatetime(X509_get_notBefore([self cert]));
    return [NSString stringWithCString:beginTime.c_str() encoding:NSUTF8StringEncoding];
}

-(NSString*)getValidTo
{
    std::string endTime = asn1datetime_isodatetime(X509_get_notAfter([self cert]));
    return [NSString stringWithCString:endTime.c_str() encoding:NSUTF8StringEncoding];
}

-(NSMutableArray*) getOcspURLs
{
    NSMutableArray *list = [[NSMutableArray alloc]init];
    STACK_OF(OPENSSL_STRING) *ocsp_list = X509_get1_ocsp([self cert]);
    for (int j = 0; j < sk_OPENSSL_STRING_num(ocsp_list); j++)
    {
        [list addObject:[NSString stringWithCString:(sk_OPENSSL_STRING_value(ocsp_list, j)) encoding:NSUTF8StringEncoding]];
    }
    X509_email_free(ocsp_list);
    return list;
}
//----------------------------------------------------------------------
-(NSMutableArray*) getCrlUrls
{
    NSMutableArray *list = [[NSMutableArray alloc]init];
    int nid = NID_crl_distribution_points;
    STACK_OF(DIST_POINT) * dist_points =(STACK_OF(DIST_POINT) *)X509_get_ext_d2i([self cert], nid, NULL, NULL);
    for (int j = 0; j < sk_DIST_POINT_num(dist_points); j++)
    {
        DIST_POINT *dp = sk_DIST_POINT_value(dist_points, j);
        DIST_POINT_NAME    *distpoint = dp->distpoint;
        if (distpoint->type==0)
        {
            for (int k = 0; k < sk_GENERAL_NAME_num(distpoint->name.fullname); k++)
            {
                GENERAL_NAME *gen = sk_GENERAL_NAME_value(distpoint->name.fullname, k);
                ASN1_IA5STRING *asn1_str = gen->d.uniformResourceIdentifier;
                NSData *data = [NSData dataWithBytes:(char*)ASN1_STRING_data(asn1_str) length:ASN1_STRING_length(asn1_str)];
                NSString* str = [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding];
                [list addObject:str];
            }
        }
        else if (distpoint->type==1)//relativename X509NAME
        {
            STACK_OF(X509_NAME_ENTRY) *sk_relname = distpoint->name.relativename;
            for (int k = 0; k < sk_X509_NAME_ENTRY_num(sk_relname); k++)
            {
                X509_NAME_ENTRY *e = sk_X509_NAME_ENTRY_value(sk_relname, k);
                ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
                
                NSData *data = [NSData dataWithBytes:(char*)ASN1_STRING_data(d) length:ASN1_STRING_length(d)];
                NSString* str = [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding];
                [list addObject:str];
            }
        }
    }
    CRL_DIST_POINTS_free(dist_points);
    return list;
}

std::string asn1datetime_isodatetime(const ASN1_TIME *tm)
{
    int year=0, month=0, day=0, hour=0, min=0, sec=0;
    _asn1dateparse(tm,year,month,day,hour,min,sec);
 
    char buf[25]="";
    snprintf(buf, sizeof(buf)-1, "%04d-%02d-%02d %02d:%02d:%02d GMT", year, month, day, hour, min, sec);
    return std::string(buf);
}

void _asn1dateparse(const ASN1_TIME *time, int& year, int& month, int& day, int& hour, int& minute, int& second)
{
    const char* str = (const char*) time->data;
    size_t i = 0;
    if (time->type == V_ASN1_UTCTIME) {/* two digit year */
        year = (str[i++] - '0') * 10;
        year += (str[i++] - '0');
        year += (year < 70 ? 2000 : 1900);
    } else if (time->type == V_ASN1_GENERALIZEDTIME) {/* four digit year */
        year = (str[i++] - '0') * 1000;
        year+= (str[i++] - '0') * 100;
        year+= (str[i++] - '0') * 10;
        year+= (str[i++] - '0');
    }
    month  = (str[i++] - '0') * 10;
    month += (str[i++] - '0') - 1; // -1 since January is 0 not 1.
    day  = (str[i++] - '0') * 10;
    day += (str[i++] - '0');
    hour = (str[i++] - '0') * 10;
    hour+= (str[i++] - '0');
    minute  = (str[i++] - '0') * 10;
    minute += (str[i++] - '0');
    second  = (str[i++] - '0') * 10;
    second += (str[i++] - '0');
}

std::string asn1int(ASN1_INTEGER *bs)
{
    static const char hexbytes[] = "0123456789ABCDEF";
    std::stringstream ashex;
    for(int i=0; i<bs->length; i++)
    {
        ashex << hexbytes[ (bs->data[i]&0xf0)>>4  ] ;
        ashex << hexbytes[ (bs->data[i]&0x0f)>>0  ] ;
    }
    return ashex.str();
}


std::string issuer_one_line(X509* x509)
{
    BIO * bio_out = BIO_new(BIO_s_mem());
    X509_NAME_print(bio_out,X509_get_issuer_name(x509),0);
    BUF_MEM *bio_buf;
    BIO_get_mem_ptr(bio_out, &bio_buf);
    std::string issuer = std::string(bio_buf->data, bio_buf->length);
    BIO_free(bio_out);
    return issuer;
}

@end

