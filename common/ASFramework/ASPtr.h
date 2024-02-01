//******************************************************************************
/*++
	FileName:		ASPtr.h
	Description:

--*/
//******************************************************************************
#ifndef __ASPtr_H__
#define __ASPtr_H__
//******************************************************************************
template<typename T>
class ASPtr_NO_ReleaseAddRef : public T
{
private:
	virtual long AddRef();
	virtual long Release();
};
//******************************************************************************
template <class T>
class ASPtr
{
public:
	ASPtr(T* Ptr = NULL) throw() : m_Ptr(Ptr)
	{
		if (m_Ptr)
			m_Ptr->AddRef();
	}

	ASPtr(const ASPtr<T>& Ptr) : m_Ptr(Ptr->m_Ptr)
	{
		if (m_Ptr)
			m_Ptr->AddRef();
	}

	~ASPtr(void)
	{
		if (m_Ptr)
			m_Ptr->Release();
	}

public:
	T* operator = (T* Ptr) throw()
	{
		if (m_Ptr != Ptr)
		{
			if (m_Ptr)
				m_Ptr->Release();

			m_Ptr = Ptr;
			m_Ptr->AddRef();
		}

		return m_Ptr;
	}

	T* operator = (const ASPtr<T>& Ptr) throw()
	{
		if(m_Ptr != Ptr.m_Ptr)
		{
			if (m_Ptr)
				m_Ptr->Release();

			m_Ptr = Ptr.m_Ptr;
			m_Ptr->AddRef();
		}

		return m_Ptr;
	}

public:
	operator T* (void) const throw()
	{
		return m_Ptr;
	}

	T** operator & (void) throw()
	{
		return &m_Ptr;
	}

	ASPtr_NO_ReleaseAddRef<T>* operator-> (void) throw()
	{
		return (ASPtr_NO_ReleaseAddRef<T>* )m_Ptr;
	}

	operator bool (void) const throw()
	{
		return m_Ptr != NULL;
	}

	bool operator !() const throw()
	{
		return m_Ptr == NULL;
	}

	bool operator != (T* Ptr) const throw()
	{
		return m_Ptr != Ptr;
	}

	bool operator == (T* Ptr) const throw()
	{
		return m_Ptr == Ptr;
	}

public:
	void Release(void) throw()
	{
		T* Ptr = m_Ptr;

		if (Ptr)
		{
			m_Ptr = NULL;
			Ptr->Release();
		}
	}

	void Attach(T* Ptr) throw()
	{
		if (m_Ptr == Ptr)
			return;

		if (m_Ptr)
			m_Ptr->Release();

		m_Ptr = Ptr;
	}

	T* Detach(void) throw()
	{
		T* Ptr = m_Ptr;
		m_Ptr = NULL;
		return Ptr;
	}

protected:
	T*	m_Ptr;
};
//******************************************************************************
#endif
