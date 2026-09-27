package guiraster

// Шрифты для растрового холста.
//
// # Откуда они берутся
//
// В окне Windows гарнитура задана жёстко — Segoe UI есть на любой системе
// начиная с Vista. На Linux такого единого шрифта нет, поэтому здесь список
// кандидатов: сначала то, что метрически ближе к Segoe UI, потом то, что
// точно найдётся. Ни один шрифт в программу не встраивается: лишние
// мегабайты в бинарнике ради того, что и так лежит в системе.
//
// Если не нашлось ничего — окно скажет об этом прямо, а не нарисует пустые
// прямоугольники: «интерфейс без единой буквы» человек прочитает как
// поломку, и будет прав.

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/image/font"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/font/sfnt"

	"github.com/soways11/masquevpn/internal/gui"
)

// Кандидаты в порядке предпочтения: пропорциональные и моноширинные.
//
// DejaVu Sans шире Segoe UI примерно на десятую долю, Liberation Sans
// метрически повторяет Arial и ближе всего; Noto — запасной, он есть в
// минимальных образах.
var (
	sansCandidates = []string{
		"LiberationSans-Regular.ttf",
		"DejaVuSans.ttf",
		"NotoSans-Regular.ttf",
		"FreeSans.ttf",
		"Ubuntu-R.ttf",
	}
	sansBoldCandidates = []string{
		"LiberationSans-Bold.ttf",
		"DejaVuSans-Bold.ttf",
		"NotoSans-Bold.ttf",
		"FreeSansBold.ttf",
		"Ubuntu-B.ttf",
	}
	monoCandidates = []string{
		"LiberationMono-Regular.ttf",
		"DejaVuSansMono.ttf",
		"NotoSansMono-Regular.ttf",
		"FreeMono.ttf",
		"UbuntuMono-R.ttf",
	}
)

// searchDirs — где искать. Порядок не важен, важен охват: у разных
// дистрибутивов шрифты лежат по-разному.
var searchDirs = []string{
	"/usr/share/fonts",
	"/usr/local/share/fonts",
	"/usr/share/texmf/fonts",
}

// FontSet — набор начертаний для холста, с кешем по кеглю.
//
// Кеш нужен потому, что шрифт разбирается заново на каждый размер, а
// размеров в интерфейсе около десяти и перерисовок — по одной в секунду.
type FontSet struct {
	sans, bold, mono *sfnt.Font

	mu    sync.Mutex
	faces map[faceKey]font.Face
}

type faceKey struct {
	kind int // 0 — обычный, 1 — жирный, 2 — моноширинный
	size int // в пикселях, уже с учётом масштаба
}

// LoadFonts находит шрифты в системе.
func LoadFonts() (*FontSet, error) {
	index, err := indexFonts()
	if err != nil {
		return nil, err
	}
	set := &FontSet{faces: map[faceKey]font.Face{}}

	pick := func(names []string) *sfnt.Font {
		for _, name := range names {
			path, ok := index[name]
			if !ok {
				continue
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			f, err := sfnt.Parse(raw)
			if err != nil {
				continue
			}
			return f
		}
		return nil
	}

	set.sans = pick(sansCandidates)
	set.bold = pick(sansBoldCandidates)
	set.mono = pick(monoCandidates)

	if set.sans == nil {
		return nil, fmt.Errorf("guiraster: не нашёл ни одного подходящего шрифта; "+
			"поставьте fonts-liberation или fonts-dejavu (искал в %v)", searchDirs)
	}
	// Жирного и моноширинного может не быть — обойдёмся обычным. Это
	// заметно, но читать можно, а отказ запускаться из-за отсутствия
	// жирного начертания был бы несоразмерен.
	if set.bold == nil {
		set.bold = set.sans
	}
	if set.mono == nil {
		set.mono = set.sans
	}
	return set, nil
}

// indexFonts собирает карту «имя файла → путь». Обход каталогов один раз
// при запуске: их немного, а искать шрифт заново на каждый кегль — значит
// ходить по диску при каждой перерисовке.
func indexFonts() (map[string]string, error) {
	index := map[string]string{}
	for _, dir := range searchDirs {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil //nolint:nilerr // недоступный каталог — не повод прерывать обход
			}
			name := info.Name()
			if _, seen := index[name]; !seen {
				index[name] = path
			}
			return nil
		})
	}
	if len(index) == 0 {
		return nil, fmt.Errorf("guiraster: каталоги со шрифтами пусты или недоступны: %v", searchDirs)
	}
	return index, nil
}

// Face возвращает начертание под кегль с учётом масштаба.
func (s *FontSet) Face(f gui.Font, scale float64) font.Face {
	size := int(f.Size*scale + 0.5)
	if size < 1 {
		size = 1
	}
	kind := 0
	src := s.sans
	switch {
	case f.Mono:
		kind, src = 2, s.mono
	case f.Weight >= gui.WeightSemibold:
		kind, src = 1, s.bold
	}

	key := faceKey{kind: kind, size: size}
	s.mu.Lock()
	defer s.mu.Unlock()
	if face, ok := s.faces[key]; ok {
		return face
	}
	face, err := opentype.NewFace(src, &opentype.FaceOptions{
		Size: float64(size),
		DPI:  72, // размер задаём прямо в пикселях, поэтому DPI единичный
		// Полное хинтование: мелкий текст без него мылится ровно так же,
		// как мылился в окне Windows до перехода на AntiAliasGridFit.
		Hinting: font.HintingFull,
	})
	if err != nil {
		return nil
	}
	s.faces[key] = face
	return face
}

// Close освобождает начертания.
func (s *FontSet) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.faces {
		_ = f.Close()
	}
	s.faces = map[faceKey]font.Face{}
}
