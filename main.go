// Copyright 2021 Daniel Erat.
// All rights reserved.

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/fastly/compute-sdk-go/fsthttp"
	"github.com/gorilla/feeds"
	"github.com/mmcdole/gofeed"
)

const (
	titleLen    = 80       // max length of title text in feed, in runes
	minIDHeader = "Min-Id" // header returned by Nitter with min ID among items
)

// feedFormat describes different feed formats that can be written.
type feedFormat string

const (
	atomFormat feedFormat = "atom"
	jsonFormat feedFormat = "json"
	rssFormat  feedFormat = "rss"
)

// Fallback list of instances, pulled from
// https://github.com/zedeus/nitter/wiki/Instances on 31 July 2023. This
// list is only used if we can't automatically pull a list of working
// instances.
//
// TODO: The server that serves the list of instances throttles pretty
// aggressively, maybe we should store the list in the KV store or the
// cache.
var fallbackInstances = []string{
	"https://nitter.lacontrevoie.fr",
	"https://nitter.nixnet.services",
	"https://nitter.fdn.fr",
	"https://nitter.1d4.us",
	"https://nitter.kavin.rocks",
	"https://nitter.unixfox.eu",
	"https://nitter.moomoo.me",
	"https://nitter.weiler.rocks",
	"https://nitter.sethforprivacy.com",
	"https://nitter.nl",
	"https://nitter.mint.lgbt",
	"https://nitter.esmailelbob.xyz",
	"https://tw.artemislena.eu",
	"https://nitter.tiekoetter.com",
	"https://nitter.privacy.com.de",
	"https://nitter.cz",
	"https://nitter.privacydev.net",
	"https://unofficialbird.com",
	"https://nitter.projectsegfau.lt",
	"https://nitter.eu.projectsegfau.lt",
	"https://nitter.in.projectsegfau.lt",
	"https://singapore.unofficialbird.com",
	"https://canada.unofficialbird.com",
	"https://india.unofficialbird.com",
	"https://nederland.unofficialbird.com",
	"https://uk.unofficialbird.com",
	"https://nitter.d420.de",
	"https://nitter.caioalonso.com",
	"https://nitter.at",
	"https://nitter.nicfab.eu",
	"https://bird.habedieeh.re",
	"https://nitter.hostux.net",
	"https://nitter.us.projectsegfau.lt",
	"https://nitter.kling.gg",
	"https://nitter.tux.pizza",
	"https://nitter.onthescent.xyz",
	"https://nitter.private.coffee",
	"https://nitter.oksocial.net",
	"https://nitter.services.woodland.cafe",
	"https://nitter.dafriser.be",
	"https://nitter.catsarch.com",
}

func main() {
	var opts handlerOptions

	opts.cycle = true
	opts.debugAuthors = true
	opts.format = feedFormat(atomFormat)
	opts.rewrite = true
	opts.timeout = 10 * time.Second

	log.Printf(
		"Received request on %s for service version %s",
		os.Getenv("FASTLY_HOSTNAME"),
		os.Getenv("FASTLY_SERVICE_VERSION"),
	)

	instances := getCurrentInstances(opts)
	if len(instances) == 0 {
		log.Print("Using fallback instance list")
		instances = fallbackInstances
	}

	log.Printf("Using %v instance(s):\n  %v", len(instances), strings.Join(instances, "\n  "))

	hnd, err := newHandler("", strings.Join(instances, ","), opts)
	if err != nil {
		log.Fatal("Failed creating handler: ", err)
	}

	fsthttp.Serve(hnd)
}

// handler implements fsthttp.Handler to accept GET requests for RSS feeds.
type handler struct {
	base      *url.URL
	instances []*url.URL
	opts      handlerOptions
}

type handlerOptions struct {
	cycle        bool // cycle through instances
	timeout      time.Duration
	format       feedFormat
	rewrite      bool // rewrite tweet content to point at Twitter
	debugAuthors bool // log per-author tweet counts
}

func getCurrentInstances(opts handlerOptions) []string {
	const host = "status.d420.de"
	const url = "https://status.d420.de/api/v1/instances"

	bopts := &fsthttp.BackendOptions{}
	bopts = bopts.ConnectTimeout(opts.timeout)
	bopts = bopts.FirstByteTimeout(opts.timeout)
	bopts = bopts.BetweenBytesTimeout(opts.timeout)
	bopts = bopts.UseSSL(true)
	bopts = bopts.SNIHostname(host)

	b, err := fsthttp.RegisterDynamicBackend(host, host, bopts)
	if err != nil {
		log.Printf("Failed registering backend: %v", err)
		return nil
	}

	req, err := fsthttp.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Failed creating request: %v", err)
		return nil
	}

	resp, err := req.Send(context.Background(), b.Name())
	if err != nil {
		log.Printf("Failed sending request to %s: %v", url, err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != fsthttp.StatusOK {
		log.Printf("Got unexpected status code from %s: %v", url, resp.StatusCode)
		d, _ := io.ReadAll(resp.Body)
		log.Printf("Response body: %s", d)
		return nil
	}

	var jsonResp struct {
		Hosts []struct {
			URL     string `json:"url"`
			RSS     bool   `json:"rss"`
			Healthy bool   `json:"healthy"`
		} `json:"hosts"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&jsonResp); err != nil {
		log.Printf("Failed decoding response from %s: %v", url, err)
		return nil
	}

	var instances []string
	for _, host := range jsonResp.Hosts {
		if host.RSS && host.Healthy {
			instances = append(instances, host.URL)
		}
	}

	return instances
}

func newHandler(base, instances string, opts handlerOptions) (*handler, error) {
	hnd := &handler{
		opts: opts,
	}

	if base != "" {
		var err error
		if hnd.base, err = url.Parse(base); err != nil {
			return nil, fmt.Errorf("failed parsing %q: %v", base, err)
		}
	}

	for _, in := range strings.Split(instances, ",") {
		// Hack to permit trailing commas to make it easier to comment out instances in configs.
		if in == "" {
			continue
		}
		u, err := url.Parse(in)
		if err != nil {
			return nil, fmt.Errorf("failed parsing %q: %v", in, err)
		}
		hnd.instances = append(hnd.instances, u)
	}
	if len(hnd.instances) == 0 {
		return nil, errors.New("no instances supplied")
	}

	return hnd, nil
}

var (
	// Matches comma-separated Twitter usernames with an optional /media, /search, or /with_replies suffix
	// supported by Nitter's RSS handler (https://github.com/zedeus/nitter/blob/master/src/routes/rss.nim).
	// Ignores any leading junk that might be present in the path e.g. when proxying a prefix to FastCGI.
	userRegexp = regexp.MustCompile(`[_a-zA-Z0-9,]+(/(media|search|with_replies))?$`)

	// Matches valid query parameters to forward to Nitter.
	queryRegexp = regexp.MustCompile(`^max_position=[^&]+$`)
)

func (hnd *handler) ServeHTTP(ctx context.Context, w fsthttp.ResponseWriter, req *fsthttp.Request) {
	if req.Method != fsthttp.MethodGet {
		fsthttp.Error(w, "Only GET supported", fsthttp.StatusMethodNotAllowed)
		return
	}

	// Sigh.
	if strings.HasSuffix(req.URL.Path, "favicon.ico") {
		fsthttp.Error(w, "File not found", fsthttp.StatusNotFound)
		return
	}

	user := userRegexp.FindString(req.URL.Path)
	if user == "" {
		fsthttp.Error(w, "Invalid user", fsthttp.StatusBadRequest)
		return
	}
	var query string
	if queryRegexp.MatchString(req.URL.RawQuery) {
		query = req.URL.RawQuery
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	start := r.Intn(len(hnd.instances))

	for i := 0; i < len(hnd.instances); i++ {
		in := hnd.instances[(start+i)%len(hnd.instances)]
		b, loc, minID, err := hnd.fetch(in, user, query)
		if err != nil {
			log.Printf("Failed fetching %v from %v: %v", user, in, err)
			continue
		}
		w.Header().Set(minIDHeader, minID)
		if err := hnd.rewrite(w, b, user, loc); err != nil {
			log.Printf("Failed rewriting %v from %v: %v", user, in, err)
			continue
		}
		return
	}
	fsthttp.Error(w, "Couldn't get feed from any instances", fsthttp.StatusInternalServerError)
}

// fetch fetches user's feed from supplied Nitter instance.
// user follows the format used by Nitter: it can be a single username or a comma-separated
// list of usernames, with an optional /media, /search, or /with_replies suffix.
// If query is non-empty, it will be passed to the instance.
// The response body, final location (after redirects), and Min-Id header value are returned.
func (hnd *handler) fetch(instance *url.URL, user, query string) (
	body []byte, loc *url.URL, minID string, err error,
) {
	u := *instance
	u.Path = path.Join(u.Path, user, "rss")
	u.RawQuery = query

	log.Print("Fetching ", u.String())

	bopts := &fsthttp.BackendOptions{}
	bopts = bopts.ConnectTimeout(hnd.opts.timeout)
	bopts = bopts.FirstByteTimeout(hnd.opts.timeout)
	bopts = bopts.BetweenBytesTimeout(hnd.opts.timeout)
	bopts = bopts.UseSSL(true)
	bopts = bopts.SNIHostname(instance.Host)

	b, err := fsthttp.RegisterDynamicBackend(
		instance.Host,
		instance.Host,
		bopts,
	)
	if err != nil {
		return nil, nil, "", err
	}

	req, err := fsthttp.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, nil, "", err
	}

	resp, err := req.Send(context.Background(), b.Name())
	if err != nil {
		return nil, nil, "", err
	}
	defer resp.Body.Close()
	loc = resp.Request.URL
	if resp.StatusCode != fsthttp.StatusOK {
		return nil, loc, "", fmt.Errorf("server returned %v", resp.StatusCode)
	}
	body, err = io.ReadAll(resp.Body)
	return body, loc, resp.Header.Get(minIDHeader), err
}

// rewrite parses user's feed from b and rewrites it to w.
func (hnd *handler) rewrite(w fsthttp.ResponseWriter, b []byte, user string, loc *url.URL) error {
	of, err := gofeed.NewParser().ParseString(string(b))
	if err != nil {
		return err
	}

	log.Printf("Rewriting %v item(s) for %v", len(of.Items), user)

	feed := &feeds.Feed{
		Title:       of.Title,
		Link:        &feeds.Link{Href: rewriteTwitterURL(of.Link)},
		Description: "Twitter feed for " + user,
	}
	if of.UpdatedParsed != nil {
		feed.Updated = *of.UpdatedParsed
	}
	if of.Author != nil {
		feed.Author = &feeds.Author{Name: of.Author.Name}
	}

	var img string
	if of.Image != nil {
		img = rewriteIconURL(of.Image.URL)
		feed.Image = &feeds.Image{Url: img}
	}

	authorCnt := make(map[string]int)

	for _, oi := range of.Items {
		// The Content field seems to be empty. gofeed appears to instead return the
		// content (often including HTML) in the Description field.
		content := oi.Description
		if hnd.opts.rewrite {
			if content, err = rewriteContent(oi.Description, loc); err != nil {
				return err
			}
		}

		item := &feeds.Item{
			Title:   oi.Title,
			Link:    &feeds.Link{Href: rewriteTwitterURL(oi.Link)},
			Id:      rewriteTwitterURL(oi.GUID),
			Content: content,
		}

		// When writing a JSON feed, the feeds package seems to expect the Description field to
		// contain text rather than HTML.
		if hnd.opts.format == jsonFormat {
			item.Description = oi.Title
		} else {
			item.Description = content
		}

		if oi.PublishedParsed != nil {
			item.Created = *oi.PublishedParsed
		}
		if oi.UpdatedParsed != nil {
			item.Updated = *oi.UpdatedParsed
		}

		if oi.Author != nil && oi.Author.Name != "" {
			item.Author = &feeds.Author{Name: oi.Author.Name}
		} else if oi.DublinCoreExt != nil && len(oi.DublinCoreExt.Creator) > 0 {
			// Nitter seems to use <dc:creator> for the original author in retweets.
			item.Author = &feeds.Author{Name: oi.DublinCoreExt.Creator[0]}
		}

		authorCnt[item.Author.Name] += 1

		// Nitter dumps the entire content into the title.
		// This looks ugly in Feedly, so truncate it.
		if ut := []rune(item.Title); len(ut) > titleLen {
			item.Title = string(ut[:titleLen-1]) + "…"
		}

		feed.Add(item)
	}

	// I've been seeing an occasional bug where a given feed will suddenly include a bunch of
	// unrelated tweets from some other feed. I'm assuming it's caused by one or more buggy Nitter
	// instances.
	if hnd.opts.debugAuthors {
		log.Printf("Authors for %v: %v", user, authorCnt)
	}

	switch hnd.opts.format {
	case atomFormat:
		af := (&feeds.Atom{Feed: feed}).AtomFeed()
		af.Icon = img
		af.Logo = img
		s, err := feeds.ToXML(af)
		if err != nil {
			return err
		}
		w.Header().Set("Content-Type", "application/atom+xml; charset=UTF-8")
		_, err = io.WriteString(w, s)
		return err
	case jsonFormat:
		jf := (&feeds.JSON{Feed: feed}).JSONFeed()
		if hnd.base != nil {
			u := *hnd.base
			u.Path = path.Join(u.Path, user)
			jf.FeedUrl = u.String()
		}
		jf.Favicon = img
		jf.Icon = img
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		return enc.Encode(jf)
	case rssFormat:
		w.Header().Set("Content-Type", "application/rss+xml; charset=UTF-8")
		return feed.WriteRss(w)
	default:
		return fmt.Errorf("unknown format %q", hnd.opts.format)
	}
}

const (
	start         = `(?:^|\b)`
	end           = `(?:$|\b)`
	scheme        = `https?://`
	host          = `[a-zA-Z0-9][-a-zA-Z0-9]*\.[-.a-zA-Z0-9]+`
	slash         = `(?:/|%2F)` // Nitter seems to incorrectly (?) escape slashes in some cases.
	invidiousHost = `invidious\.[-.a-zA-Z0-9]+`
)

// encPicRegexp matches weird Nitter RULs with base64-encoded image paths,
// e.g. "https://example.org/pic/enc/bWVkaWEvRm1Jc0R3SldRQUFKV2w4LmpwZw==".
// We can't use |end| here since \b expects \w on one side and \W on the other,
// but we may have a URL ending with '=' followed by '"' (both \W).
var encPicRegexp = regexp.MustCompile(start +
	// TODO: https://github.com/zedeus/nitter/blob/master/src/utils.nim also has code
	// for /video/enc/ and /pic/orig/enc/. I'm not bothering to decode those yet since
	// there aren't any rewrite patterns to further rewrite the resulting URLs.
	`(` + scheme + host + `/pic/)` + // group 1: start of URL
	`enc/` +
	// See "5. Base 64 Encoding with URL and Filename Safe Alphabet" from RFC 4648.
	`([-_=a-zA-Z0-9]+)`) // group 2: base64-encoded end of URL

// decodeEncPicURL rewrites a URL matched by encPicRegexp to instead be the corresponding
// non-encoded Nitter URL, e.g. "https://example.org/pic/media/FmN39CgWQAEkNAO.jpg".
// If the URL is not matched by encPicRegexp, it will be returned unmodified.
func decodeEncPicURL(u string) string {
	ms := encPicRegexp.FindStringSubmatch(u)
	if ms == nil {
		return u
	}
	dec, err := base64.URLEncoding.DecodeString(ms[2])
	if err != nil {
		log.Printf("Failed base64-decoding %q: %v", ms[2], err)
		return u
	}
	return ms[1] + string(dec)
}

// iconRegexp exactly matches a Nitter profile image URL,
// e.g. "https://example.org/pic/profile_images%2F1234567890%2F_AbQ3eRu_400x400.jpg".
// At some point, Nitter seems to have started adding "/pbs.twimg.com" after "/pic".
var iconRegexp = regexp.MustCompile(`^` +
	scheme + host +
	`/pic(?:/pbs\.twimg\.com)?` + slash +
	`profile_images` + slash +
	`(\d+)` + // group 1: ID
	slash +
	`([-_.a-zA-Z0-9]+)$`) // group 2: ID, size, extension

// rewriteIconURL rewrites a Nitter profile image URL to the corresponding Twitter URL.
func rewriteIconURL(u string) string {
	// First decode base64-encoded /pic/enc paths, which are used by some Nitter instances.
	u = decodeEncPicURL(u)
	ms := iconRegexp.FindStringSubmatch(u)
	if ms == nil {
		return u
	}
	return fmt.Sprintf("https://pbs.twimg.com/profile_images/%v/%v", ms[1], ms[2])
}

// rewritePatterns is used by rewriteContent to rewrite URLs within tweets.
var rewritePatterns = []struct {
	re *regexp.Regexp
	fn func(ms []string) string // matching groups from re are passed
}{
	{
		// Before doing anything else, rewrite base64-encoded image paths.
		// Later rules may rewrite these further.
		encPicRegexp,
		func(ms []string) string { return decodeEncPicURL(ms[0]) },
	},
	{
		// Nitter URL referring to a tweet, e.g.
		// "https://example.org/someuser/status/1234567890#m" or
		// "https://example.org/i/web/status/1234567890".
		// The scheme is optional.
		regexp.MustCompile(start +
			`(` + scheme + `)?` + // group 1: optional scheme
			host + `/` +
			`([_a-zA-Z0-9]+|i/web)` + // group 2: username or weird 'i/web' thing
			slash + `status` + slash +
			`(\d+)` + // group 3: tweet ID
			`(?:#m)?` + // nitter adds these hashes
			end),
		func(ms []string) string {
			u := fmt.Sprintf("twitter.com/%v/status/%v", ms[2], ms[3])
			if ms[1] != "" {
				u = "https://" + u
			}
			return u
		},
	},
	{
		// Nitter URL referring to an image, e.g.
		// "https://example.org/pic/media%2FA3B6MFcQXBBcIa2.jpg".
		regexp.MustCompile(start +
			scheme + host + `/pic` + slash + `media` + slash +
			`([-_a-zA-Z0-9]+)` + // group 1: image ID
			`\.(jpg|png)` + // group 2: extension
			end),
		func(ms []string) string { return fmt.Sprintf("https://pbs.twimg.com/media/%v?format=%v", ms[1], ms[2]) },
	},
	{
		// Nitter URL referring to a video, e.g.
		// "https://example.org/pic/video.twimg.com%2Ftweet_video%2FA47B3e5XMAM233z.mp4".
		regexp.MustCompile(start +
			scheme + host + `/pic` + slash + `video.twimg.com` + slash + `tweet_video` + slash +
			`([-_.a-zA-Z0-9]+)` + // group 1: video name and extension
			end),
		func(ms []string) string { return "https://video.twimg.com/tweet_video/" + ms[1] },
	},
	{
		// Nitter URL referring to a video thumbnail, e.g.
		// "http://example.org/pic/tweet_video_thumb%2FA47B3e5XMAM233z.jpg".
		regexp.MustCompile(start +
			scheme + host + `/pic` + slash + `tweet_video_thumb` + slash +
			`([-_.a-zA-Z0-9]+)` + // group 1: thumbnail name and extension
			end),
		func(ms []string) string { return "https://video.twimg.com/tweet_video_thumb/" + ms[1] },
	},
	{
		// Nitter URL referring to an external (?) video thumbnail, e.g.
		// "https://example.org/pic/ext_tw_video_thumb%2F3516826898992848541%2Fpu%2Fimg%2FaB-5ho5t2AlIL7sK.jpg".
		regexp.MustCompile(start +
			scheme + host + `/pic` + slash + `ext_tw_video_thumb` + slash +
			`(\d+)` + // group 1: tweet ID (?)
			slash + `pu` + slash + `img` + slash +
			`([-_.a-zA-Z0-9]+)` + // group 2: thumbnail name and extension
			end),
		func(ms []string) string {
			return "https://pbs.twimg.com/ext_tw_video_thumb/" + ms[1] + "/pu/img/" + ms[2]
		},
	},
	{
		// Invidious URL referring to a YouTube URL, e.g.
		// "https://example.org/watch?v=AxWGuBDrA1u". The scheme is optional.
		regexp.MustCompile(start +
			`(` + scheme + `)?` + // group 1: optional scheme
			host + `/watch\?v=` +
			`([-_a-zA-Z0-9]+)` + // group 2: video ID
			end),
		func(ms []string) string {
			u := "youtube.com/watch?v=" + ms[2]
			if ms[1] != "" {
				u = "https://" + u
			}
			return u
		},
	},
	{
		// Invidious URL without /watch?v=, e.g.
		// "https://invidious.snopyta.org/AxWGuBDrA1u". The scheme is optional.
		regexp.MustCompile(start +
			`(` + scheme + `)?` + // group 1: optional scheme
			invidiousHost + `/` +
			`([-_a-zA-Z0-9]{8,})` + // group 2: video ID
			end),
		func(ms []string) string {
			u := "youtube.com/watch?v=" + ms[2]
			if ms[1] != "" {
				u = "https://" + u
			}
			return u
		},
	},
}

// rewriteContent rewrites a tweet's HTML content fetched from loc.
// Some public Nitter instances seem to be misconfigured, e.g. rewriting URLs to
// start with "http://localhost", so we just modify all URLs that look like they
// can be served by Twitter.
func rewriteContent(s string, loc *url.URL) (string, error) {
	// It'd be better to parse the HTML instead of using regular expressions, but that's quite
	// painful to do (see https://github.com/derat/twittuh) so I'm trying to avoid it for now.
	for _, rw := range rewritePatterns {
		s = rw.re.ReplaceAllStringFunc(s, func(o string) string {
			return rw.fn(rw.re.FindStringSubmatch(o))
		})
	}

	// Match all remaining URLs served by the instance and change them to use twitter.com:
	// https://codeberg.org/derat/nitter-rss-proxy/issues/13
	if loc != nil {
		// Match both http:// and https:// since some instances seem to be configured
		// to always use http:// for links.
		re, err := regexp.Compile(`\bhttps?://` + regexp.QuoteMeta(loc.Host) + `/[^" ]*`)
		if err != nil {
			return s, err
		}
		s = re.ReplaceAllStringFunc(s, func(o string) string { return rewriteTwitterURL(o) })
	}

	// TODO: Fetch embedded tweets.

	// Make sure that newlines are preserved.
	s = strings.ReplaceAll(s, "\n", "<br>")

	return s, nil
}

// rewriteTwitterURL rewrites orig's scheme and hostname to be https://twitter.com.
func rewriteTwitterURL(orig string) string {
	u, err := url.Parse(orig)
	if err != nil {
		log.Printf("Failed parsing %q: %v", orig, err)
		return orig
	}
	u.Scheme = "https"
	u.Host = "twitter.com"
	u.Fragment = "" // get rid of weird '#m' fragments added by Nitter
	return u.String()
}
