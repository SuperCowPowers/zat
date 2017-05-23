"""NGram utilities that might be useful"""
from __future__ import print_function


def compute_ngrams(word_list, S=3, T=3):
    """Compute NGrams in the word_list from [S-T)
        Args:
            word_list (list): A list of words to compute ngram set from
            S (int): The smallest NGram (default=3)
            T (int): The biggest NGram (default=3)
    """
    _ngrams = []
    if isinstance(word_list, str):
        word_list = [word_list]
    for word in word_list:
        for n in range(S, T+1):
            _ngrams += zip(*(word[i:] for i in range(n)))
    return [''.join(_ngram) for _ngram in _ngrams]


def ngram_count(word, ngrams):
    """Compute the number of matching NGrams in the given word"""
    return len(set(ngrams).intersection(compute_ngrams([word])))


def test():
    """Test the ngram methods"""
    domains = ['google', 'facebook', 'apple']
    compute_ngrams(domains, 2, 5)
    ngrams = compute_ngrams(domains)
    print('NGrams: {:s}'.format(str(list(ngrams))))
    print(ngram_count('foogle', ngrams))
    print(ngram_count('mybook', ngrams))


if __name__ == '__main__':
    test()
