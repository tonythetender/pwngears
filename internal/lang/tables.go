package lang

import "math"

// englishLetterFreq is the standard English letter frequency in percent, A..Z.
var englishLetterFreq = [26]float64{
	8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153,
	0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056,
	2.758, 0.978, 2.360, 0.150, 1.974, 0.074,
}

// commonWords is a compact list of the most frequent English words. It serves
// two purposes: a word-presence bonus, and (since common words dominate real
// text) the source corpus from which the bigram/trigram log-probability tables
// are derived at init. This keeps the model fully self-contained and dep-free.
//
// A fuller model (e.g. a true quadgram table) would need an embedded corpus;
// the trigram model built from this list is strong enough for Magic ranking,
// Vigenere recovery, and substitution hill-climbing on reasonable inputs.
var commonWords = []string{
	"the", "of", "and", "to", "in", "is", "you", "that", "it", "he", "was", "for",
	"on", "are", "as", "with", "his", "they", "at", "be", "this", "have", "from",
	"or", "one", "had", "by", "word", "but", "not", "what", "all", "were", "we",
	"when", "your", "can", "said", "there", "use", "an", "each", "which", "she",
	"do", "how", "their", "if", "will", "up", "other", "about", "out", "many",
	"then", "them", "these", "so", "some", "her", "would", "make", "like", "him",
	"into", "time", "has", "look", "two", "more", "write", "go", "see", "number",
	"no", "way", "could", "people", "than", "first", "water", "been", "call",
	"who", "its", "now", "find", "long", "down", "day", "did", "get", "come",
	"made", "may", "part", "over", "new", "sound", "take", "only", "little",
	"work", "know", "place", "year", "live", "back", "give", "most", "very",
	"after", "thing", "our", "just", "name", "good", "sentence", "man", "think",
	"say", "great", "where", "help", "through", "much", "before", "line", "right",
	"too", "mean", "old", "any", "same", "tell", "follow", "came", "want", "show",
	"also", "around", "form", "three", "small", "set", "put", "end", "does",
	"another", "well", "large", "must", "big", "even", "such", "because", "turn",
	"here", "why", "ask", "went", "men", "read", "need", "land", "different",
	"home", "move", "try", "kind", "hand", "picture", "again", "change", "off",
	"play", "spell", "air", "away", "animal", "house", "point", "page", "letter",
	"mother", "answer", "found", "study", "still", "learn", "should", "world",
	"high", "every", "near", "add", "food", "between", "own", "below", "country",
	"plant", "last", "school", "father", "keep", "tree", "never", "start", "city",
	"earth", "eye", "light", "thought", "head", "under", "story", "saw", "left",
	"few", "while", "along", "might", "close", "something", "seem", "next", "hard",
	"open", "example", "begin", "life", "always", "those", "both", "paper",
	"together", "got", "group", "often", "run", "important", "until", "children",
	"side", "feet", "car", "mile", "night", "walk", "white", "sea", "began",
	"grow", "took", "river", "four", "carry", "state", "once", "book", "hear",
	"stop", "without", "second", "later", "miss", "idea", "enough", "eat", "face",
	"watch", "far", "indian", "really", "almost", "let", "above", "girl",
	"sometimes", "mountain", "cut", "young", "talk", "soon", "list", "song",
	"being", "leave", "family", "flag", "secret", "message", "system", "access",
}

var (
	monoLog [26]float64
	biLog   map[string]float64
	triLog  map[string]float64
	wordSet map[string]bool

	biFloor  float64
	triFloor float64
	triBest  float64
)

func init() {
	// Monogram log-probabilities from the standard frequency table.
	for i, f := range englishLetterFreq {
		if f <= 0 {
			f = 0.01
		}
		monoLog[i] = math.Log(f / 100.0)
	}

	wordSet = make(map[string]bool, len(commonWords))
	biCount := map[string]int{}
	triCount := map[string]int{}
	biTotal, triTotal := 0, 0
	for _, w := range commonWords {
		wordSet[w] = true
		for i := 0; i+1 < len(w); i++ {
			biCount[w[i:i+2]]++
			biTotal++
		}
		for i := 0; i+2 < len(w); i++ {
			triCount[w[i:i+3]]++
			triTotal++
		}
	}

	const k = 0.5
	biV := 26.0 * 26.0
	triV := 26.0 * 26.0 * 26.0
	biFloor = math.Log(k / (float64(biTotal) + k*biV))
	triFloor = math.Log(k / (float64(triTotal) + k*triV))

	biLog = make(map[string]float64, len(biCount))
	for g, c := range biCount {
		biLog[g] = math.Log((float64(c) + k) / (float64(biTotal) + k*biV))
	}
	triLog = make(map[string]float64, len(triCount))
	triBest = triFloor
	for g, c := range triCount {
		lp := math.Log((float64(c) + k) / (float64(triTotal) + k*triV))
		triLog[g] = lp
		if lp > triBest {
			triBest = lp
		}
	}
}
