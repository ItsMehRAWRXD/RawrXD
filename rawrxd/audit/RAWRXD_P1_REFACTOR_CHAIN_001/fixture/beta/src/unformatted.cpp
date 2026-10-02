// Deliberately unformatted fixture for the format cell.
// Authored defects: hard tabs, trailing whitespace, three consecutive blank
// lines, and no trailing newline on the final line.
#include "report_sink.h"

namespace beta {

double    passthrough(   const Report& r )
{
	double out = r.value;   
	return out;
}

double    second( const Report& r )
{
	return r.value * 3.0;
}

}  // namespace beta


