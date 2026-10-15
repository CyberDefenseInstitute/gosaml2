package idp

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	saml2 "github.com/russellhaering/gosaml2/v2"
	"github.com/russellhaering/gosaml2/v2/internal/testutil/require"
	dsig "github.com/russellhaering/gosaml2/v2/internal/xmldsig"
	"github.com/russellhaering/gosaml2/v2/internal/xmltree"
	"github.com/russellhaering/gosaml2/v2/types"
)

// TestSPCanonicalizer は全6方式と未指定時の継承を対象に、並行生成した最終XMLの
// Response・Assertion・エラーResponseの方式と署名を検証し、共有署名器が変わらないことを確認する。
func TestSPCanonicalizer(t *testing.T) {
	provider, keyStore := testIdentityProvider(t)
	defaultCanonicalizer := saml2.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	provider.SignatureCanonicalizer = defaultCanonicalizer
	canonicalizers := []struct {
		name  string
		value saml2.Canonicalizer
	}{
		{"inherit", nil},
		{"inclusive-1.0", saml2.MakeC14N10RecCanonicalizer()},
		{"inclusive-1.0-comments", saml2.MakeC14N10WithCommentsCanonicalizer()},
		{"exclusive-1.0", saml2.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")},
		{"exclusive-1.0-comments", saml2.MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList("")},
		{"inclusive-1.1", saml2.MakeC14N11Canonicalizer()},
		{"inclusive-1.1-comments", saml2.MakeC14N11WithCommentsCanonicalizer()},
	}
	for _, test := range canonicalizers {
		entityID := "https://" + test.name + ".test/metadata"
		provider.ServiceProviders[entityID] = &SPConfig{
			EntityID:               entityID,
			ACSURLs:                []string{"https://sp.test/acs"},
			SignatureCanonicalizer: test.value,
		}
	}
	cert, err := x509.ParseCertificate(keyStore.Cert)
	require.NoError(t, err)
	cachedSigner, err := provider.Signer()
	require.NoError(t, err)

	for _, test := range canonicalizers {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			entityID := "https://" + test.name + ".test/metadata"
			canonicalizer := test.value
			if canonicalizer == nil {
				canonicalizer = defaultCanonicalizer
			}
			verifier := &dsig.Verifier{
				TrustedCerts: []*x509.Certificate{cert},
				Clock:        func() time.Time { return testTime },
			}
			for range 3 {
				doc, _, err := provider.BuildResponseDocumentContext(context.Background(), entityID, &AssertionParams{
					NameID:     "user@example.com",
					Attributes: []types.Attribute{{Name: "role", Values: []types.AttributeValue{{Value: "admin", Type: "xs:string"}}}},
				})
				require.NoError(t, err)
				data, err := doc.WriteToBytes()
				require.NoError(t, err)
				parsed, err := xmltree.Parse(data)
				require.NoError(t, err)
				root := parsed.Root()
				for _, element := range []*xmltree.Element{root, root.SelectElement("saml:Assertion")} {
					require.NotNil(t, element)
					method := element.SelectElement("ds:Signature").SelectElement("ds:SignedInfo").SelectElement("ds:CanonicalizationMethod")
					require.Equal(t, string(canonicalizer.Algorithm()), method.SelectAttrValue("Algorithm", ""))
					transforms := element.SelectElement("ds:Signature").SelectElement("ds:SignedInfo").SelectElement("ds:Reference").SelectElement("ds:Transforms").ChildElements()
					require.Equal(t, string(canonicalizer.Algorithm()), transforms[len(transforms)-1].SelectAttrValue("Algorithm", ""))
					_, err = verifier.Verify(element)
					require.NoError(t, err)
				}
				errorDoc, err := provider.BuildErrorResponseDocument(entityID, saml2.StatusCodeResponder, "_request", "https://sp.test/acs")
				require.NoError(t, err)
				data, err = errorDoc.WriteToBytes()
				require.NoError(t, err)
				parsed, err = xmltree.Parse(data)
				require.NoError(t, err)
				method := parsed.Root().SelectElement("ds:Signature").SelectElement("ds:SignedInfo").SelectElement("ds:CanonicalizationMethod")
				require.Equal(t, string(canonicalizer.Algorithm()), method.SelectAttrValue("Algorithm", ""))
				_, err = verifier.Verify(parsed.Root())
				require.NoError(t, err)
				require.Equal(t, defaultCanonicalizer, cachedSigner.Canonicalizer)
			}
		})
	}
}

// TestSPCanonicalizerResolver はresolverで得たSPの方式を適用し、IdP既定値が未設定の
// 既存SPではCanonical XML 1.1が維持されることを生成XMLの方式と署名で確認する。
func TestSPCanonicalizerResolver(t *testing.T) {
	provider, keyStore := testIdentityProvider(t)
	config := &SPConfig{EntityID: "https://dynamic.test/metadata", ACSURLs: []string{"https://sp.test/acs"}}
	provider.ServiceProviderResolver = &testServiceProviderResolver{sp: config}
	cert, err := x509.ParseCertificate(keyStore.Cert)
	require.NoError(t, err)
	verifier := &dsig.Verifier{TrustedCerts: []*x509.Certificate{cert}, Clock: func() time.Time { return testTime }}
	for _, canonicalizer := range []saml2.Canonicalizer{nil, saml2.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")} {
		config.SignatureCanonicalizer = canonicalizer
		expected := canonicalizer
		if expected == nil {
			expected = saml2.MakeC14N11Canonicalizer()
		}
		doc, _, err := provider.BuildResponseDocumentContext(context.Background(), config.EntityID, &AssertionParams{NameID: "user@example.com"})
		require.NoError(t, err)
		data, err := doc.WriteToBytes()
		require.NoError(t, err)
		parsed, err := xmltree.Parse(data)
		require.NoError(t, err)
		for _, element := range []*xmltree.Element{parsed.Root(), parsed.Root().SelectElement("saml:Assertion")} {
			method := element.SelectElement("ds:Signature").SelectElement("ds:SignedInfo").SelectElement("ds:CanonicalizationMethod")
			require.Equal(t, string(expected.Algorithm()), method.SelectAttrValue("Algorithm", ""))
			_, err = verifier.Verify(element)
			require.NoError(t, err)
		}
	}
}
